// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "Netplay.h"

#include "IopMem.h"
#include "Memory.h"
#include "SIO/Pad/Pad.h"
#include "SIO/Pad/PadDualshock2.h"
#include "VUmicro.h"

#define XXH_STATIC_LINKING_ONLY 1
#define XXH_INLINE_ALL 1
#include "xxhash.h"

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t BAD_SOCKET = INVALID_SOCKET;
#define poll WSAPoll
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t BAD_SOCKET = -1;
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <string>

namespace Netplay
{
	static constexpr u32 NUM_INPUTS = PadDualshock2::Inputs::LENGTH;
	/// Frames of input kept per side; must exceed delay + worst-case lag.
	static constexpr u32 HISTORY = 256;
	/// Each packet repeats this many recent frames, so a lost packet is covered
	/// by the next one without retransmission.
	static constexpr u32 REDUNDANCY = 8;
	static constexpr u32 HASH_INTERVAL = 60;
	static constexpr u32 HASH_HISTORY = 64;
	static constexpr u32 MAGIC = 0x4E505332; // "NPS2"

	using Clock = std::chrono::steady_clock;
	using Input = std::array<u8, NUM_INPUTS>;

	struct InputSlot
	{
		s64 frame = -1;
		Input input = {};
	};

	struct HashSlot
	{
		s64 frame = -1;
		u64 hash = 0;
	};

#pragma pack(push, 1)
	/// Wire format. Both peers run the same build on the same architecture in
	/// this prototype, so the struct is sent as-is.
	struct Packet
	{
		u32 magic;
		u8 delay;
		u8 count;
		s64 newest_frame; // frame of inputs[count - 1]
		s64 hash_frame; // -1 if no hash attached
		u64 hash;
		Input inputs[REDUNDANCY]; // oldest first
	};
#pragma pack(pop)

	static bool s_initialized = false;
	static bool s_active = false;
	static bool s_is_host = true;
	static socket_t s_socket = BAD_SOCKET;
	static sockaddr_in s_peer = {};
	static u32 s_delay = 3;
	static std::FILE* s_log = nullptr;
	static bool s_scripted = false;
	static u32 s_script_seed = 0;
	static u64 s_frames_to_run = 0;
	static u32 s_loss_percent = 0;
	/// Simulated one-way network latency for testing, in milliseconds.
	static u32 s_latency_ms = 0;

	/// Latest local controller state, written by input handlers (possibly on
	/// another thread) and sampled once per frame.
	static std::array<std::atomic<u8>, NUM_INPUTS> s_live = {};

	static std::array<InputSlot, HISTORY> s_local;
	static std::array<InputSlot, HISTORY> s_remote;
	static std::array<HashSlot, HASH_HISTORY> s_own_hashes;
	static std::array<HashSlot, HASH_HISTORY> s_peer_hashes;
	static s64 s_frame = 0;
	static s64 s_last_hash_frame = -1;
	static u64 s_last_hash = 0;
	static bool s_peer_delay_warned = false;

	// Stats, reset every log interval.
	static u32 s_sent = 0, s_received = 0, s_stalled_frames = 0;
	static double s_wait_total_ms = 0, s_wait_max_ms = 0;
	static u32 s_hash_ok = 0, s_desyncs = 0;

	static void SleepMs(int ms)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(ms));
	}

	static int SendTo(const void* data, size_t size)
	{
		return static_cast<int>(sendto(s_socket, reinterpret_cast<const char*>(data), static_cast<int>(size), 0,
			reinterpret_cast<const sockaddr*>(&s_peer), sizeof(s_peer)));
	}

	static u8 Quantize(float value)
	{
		return static_cast<u8>(std::clamp(std::lround(value * 255.0f), 0L, 255L));
	}

	static void Log(const char* format, ...)
	{
		if (!s_log)
			return;
		va_list args;
		va_start(args, format);
		std::vfprintf(s_log, format, args);
		va_end(args);
		std::fputc('\n', s_log);
		std::fflush(s_log);
	}

	static void Initialize()
	{
		s_initialized = true;
		const char* mode = std::getenv("ARMSX2_NETPLAY");
		if (!mode || (std::strcmp(mode, "host") != 0 && std::strcmp(mode, "join") != 0))
			return;
		s_is_host = std::strcmp(mode, "host") == 0;

		if (const char* path = std::getenv("ARMSX2_NETPLAY_LOG"))
			s_log = std::fopen(path, "w");
		if (const char* v = std::getenv("ARMSX2_NETPLAY_DELAY"))
			s_delay = std::clamp<u32>(static_cast<u32>(std::strtoul(v, nullptr, 10)), 1, 30);
		if (const char* v = std::getenv("ARMSX2_NETPLAY_SCRIPT"))
		{
			s_scripted = true;
			s_script_seed = static_cast<u32>(std::strtoul(v, nullptr, 10));
		}
		if (const char* v = std::getenv("ARMSX2_NETPLAY_FRAMES"))
			s_frames_to_run = std::strtoull(v, nullptr, 10);
		if (const char* v = std::getenv("ARMSX2_NETPLAY_LOSS"))
			s_loss_percent = std::min<u32>(static_cast<u32>(std::strtoul(v, nullptr, 10)), 90);
		if (const char* v = std::getenv("ARMSX2_NETPLAY_LATENCY"))
			s_latency_ms = std::min<u32>(static_cast<u32>(std::strtoul(v, nullptr, 10)), 1000);

		const u16 port = static_cast<u16>(std::strtoul(
			std::getenv("ARMSX2_NETPLAY_PORT") ? std::getenv("ARMSX2_NETPLAY_PORT") : (s_is_host ? "7777" : "7778"),
			nullptr, 10));

		const char* peer = std::getenv("ARMSX2_NETPLAY_PEER");
		const char* colon = peer ? std::strrchr(peer, ':') : nullptr;
		if (!colon)
		{
			Log("error: ARMSX2_NETPLAY_PEER must be ip:port");
			return;
		}
		const std::string peer_ip(peer, colon);
		s_peer.sin_family = AF_INET;
		s_peer.sin_port = htons(static_cast<u16>(std::strtoul(colon + 1, nullptr, 10)));
		if (inet_pton(AF_INET, peer_ip.c_str(), &s_peer.sin_addr) != 1)
		{
			Log("error: bad peer address %s", peer);
			return;
		}

#ifdef _WIN32
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
		s_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		sockaddr_in local = {};
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		local.sin_port = htons(port);
		if (s_socket == BAD_SOCKET || bind(s_socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
		{
			Log("error: can't bind UDP port %u", port);
			return;
		}
#ifdef _WIN32
		u_long nonblocking = 1;
		ioctlsocket(s_socket, FIONBIO, &nonblocking);
#else
		fcntl(s_socket, F_SETFL, fcntl(s_socket, F_GETFL, 0) | O_NONBLOCK);
#endif

		s_active = true;
		Log("netplay %s, port %u, peer %s, delay %u frames%s", s_is_host ? "host (player 1)" : "guest (player 2)", port,
			peer, s_delay, s_scripted ? ", scripted input" : "");
	}

	bool CaptureLocalInput(u32 controller, u32 bind, float value)
	{
		if (!s_initialized)
			Initialize();
		if (!s_active)
			return false;
		// The local player always uses their own port 1 bindings; netplay puts
		// them on the right port. Anything bound to other local ports is ignored.
		if (controller == 0 && bind < NUM_INPUTS)
			s_live[bind].store(Quantize(value), std::memory_order_relaxed);
		return true;
	}

	/// Same seeded generator as DeterminismTest: new buttons every 8 frames.
	static Input ScriptedInput(s64 frame)
	{
		auto mix = [](u32 n) {
			u32 x = n * 0x9E3779B1u ^ s_script_seed * 0x85EBCA77u;
			x ^= x >> 16;
			x *= 0x7FEB352Du;
			x ^= x >> 15;
			x *= 0x846CA68Bu;
			x ^= x >> 16;
			return x;
		};
		using In = PadDualshock2::Inputs;
		static constexpr u32 buttons[] = {In::PAD_UP, In::PAD_RIGHT, In::PAD_DOWN, In::PAD_LEFT, In::PAD_TRIANGLE,
			In::PAD_CIRCLE, In::PAD_CROSS, In::PAD_SQUARE, In::PAD_START, In::PAD_L1, In::PAD_R1};
		Input input = {};
		const u32 chunk = static_cast<u32>(frame / 8);
		for (u32 i = 0; i < std::size(buttons); i++)
		{
			const u32 odds = buttons[i] == In::PAD_START ? 24 : buttons[i] == In::PAD_CROSS ? 3 : 6;
			input[buttons[i]] = (mix(chunk * 31 + i) % odds) == 0 ? 255 : 0;
		}
		const int lx = static_cast<int>(mix(chunk) & 0xFF) - 128;
		input[In::PAD_L_RIGHT] = static_cast<u8>(lx > 0 ? std::min(lx * 2, 255) : 0);
		input[In::PAD_L_LEFT] = static_cast<u8>(lx < 0 ? std::min(-lx * 2, 255) : 0);
		return input;
	}

	static u64 HashState()
	{
		u64 h = XXH3_64bits(eeMem->Main, Ps2MemSize::MainRam);
		h = XXH3_64bits_withSeed(iopMem->Main, Ps2MemSize::IopRam, h);
		h = XXH3_64bits_withSeed(vuRegs[0].Mem, VU0_MEMSIZE, h);
		return XXH3_64bits_withSeed(vuRegs[1].Mem, VU1_MEMSIZE, h);
	}

	static void CompareHashes(s64 frame)
	{
		const HashSlot& own = s_own_hashes[(frame / HASH_INTERVAL) % HASH_HISTORY];
		const HashSlot& peer = s_peer_hashes[(frame / HASH_INTERVAL) % HASH_HISTORY];
		if (own.frame != frame || peer.frame != frame)
			return;
		if (own.hash == peer.hash)
		{
			s_hash_ok++;
		}
		else
		{
			s_desyncs++;
			Log("DESYNC at frame %lld: ours %016llx, peer %016llx", static_cast<long long>(frame),
				static_cast<unsigned long long>(own.hash), static_cast<unsigned long long>(peer.hash));
		}
	}

	/// Packets held back to simulate latency. A dedicated thread sends each one
	/// exactly when due, independent of the emulator's frame timing.
	static std::deque<std::pair<Clock::time_point, Packet>> s_outgoing;
	static std::mutex s_outgoing_mutex;
	static std::condition_variable s_outgoing_cv;
	static bool s_latency_thread_started = false;

	static void LatencyThread()
	{
		std::unique_lock lock(s_outgoing_mutex);
		for (;;)
		{
			if (s_outgoing.empty())
			{
				s_outgoing_cv.wait(lock);
				continue;
			}
			const Clock::time_point due = s_outgoing.front().first;
			if (Clock::now() < due)
			{
				s_outgoing_cv.wait_until(lock, due);
				continue;
			}
			const Packet packet = s_outgoing.front().second;
			s_outgoing.pop_front();
			lock.unlock();
			SendTo(&packet, sizeof(Packet));
			lock.lock();
		}
	}


	static void Send()
	{
		const s64 newest = s_frame + s_delay;
		Packet packet = {};
		packet.magic = MAGIC;
		packet.delay = static_cast<u8>(s_delay);
		packet.newest_frame = newest;
		// Inputs exist from frame `delay` on; earlier frames are neutral by definition.
		const s64 available = newest - static_cast<s64>(s_delay) + 1;
		packet.count = static_cast<u8>(std::clamp<s64>(available, 0, REDUNDANCY));
		for (u32 i = 0; i < packet.count; i++)
		{
			const s64 frame = newest - packet.count + 1 + i;
			packet.inputs[i] = s_local[frame % HISTORY].input;
		}
		packet.hash_frame = s_last_hash_frame;
		packet.hash = s_last_hash;

		s_sent++;
		if (s_loss_percent && static_cast<u32>(std::rand() % 100) < s_loss_percent)
			return; // simulated loss
		if (s_latency_ms == 0)
		{
			SendTo(&packet, sizeof(packet));
			return;
		}
		if (!s_latency_thread_started)
		{
			s_latency_thread_started = true;
			std::thread(LatencyThread).detach();
		}
		{
			std::lock_guard lock(s_outgoing_mutex);
			s_outgoing.emplace_back(Clock::now() + std::chrono::milliseconds(s_latency_ms), packet);
		}
		s_outgoing_cv.notify_one();
	}

	static void Receive()
	{
		Packet packet;
		for (;;)
		{
			const int len = static_cast<int>(recv(s_socket, reinterpret_cast<char*>(&packet), sizeof(packet), 0));
			if (len < 0)
				break;
			if (len != static_cast<int>(sizeof(packet)) || packet.magic != MAGIC || packet.count > REDUNDANCY)
				continue;
			s_received++;

			if (packet.delay != s_delay && !s_peer_delay_warned)
			{
				s_peer_delay_warned = true;
				Log("warning: peer uses delay %u, we use %u; inputs will not line up", packet.delay, s_delay);
			}

			for (u32 i = 0; i < packet.count; i++)
			{
				const s64 frame = packet.newest_frame - packet.count + 1 + i;
				InputSlot& slot = s_remote[frame % HISTORY];
				if (frame >= s_frame && slot.frame < frame)
				{
					slot.frame = frame;
					slot.input = packet.inputs[i];
				}
			}

			if (packet.hash_frame >= 0)
			{
				HashSlot& slot = s_peer_hashes[(packet.hash_frame / HASH_INTERVAL) % HASH_HISTORY];
				if (slot.frame != packet.hash_frame)
				{
					slot = {packet.hash_frame, packet.hash};
					CompareHashes(packet.hash_frame);
				}
			}
		}
	}

	static bool HaveRemote(s64 frame)
	{
		return frame < static_cast<s64>(s_delay) || s_remote[frame % HISTORY].frame == frame;
	}

	static const Input& InputFor(const std::array<InputSlot, HISTORY>& side, s64 frame)
	{
		static const Input neutral = {};
		const InputSlot& slot = side[frame % HISTORY];
		return slot.frame == frame ? slot.input : neutral;
	}

	static void Apply(u8 port, const Input& input)
	{
		PadBase* pad = Pad::GetPad(port);
		if (!pad || pad->GetType() != Pad::ControllerType::DualShock2)
			return;
		for (u32 i = 0; i < NUM_INPUTS; i++)
			pad->Set(i, input[i] / 255.0f);
	}

	void OnVSync()
	{
		if (!s_initialized)
			Initialize();
		if (!s_active)
			return;

		const s64 f = s_frame;

		// 1. Record our input for f + delay.
		Input local;
		if (s_scripted)
			local = ScriptedInput(f + s_delay);
		else
			for (u32 i = 0; i < NUM_INPUTS; i++)
				local[i] = s_live[i].load(std::memory_order_relaxed);
		s_local[(f + s_delay) % HISTORY] = {f + s_delay, local};

		// 2. Fingerprint the state this frame produced, for desync checks.
		if (f % HASH_INTERVAL == 0)
		{
			s_last_hash_frame = f;
			s_last_hash = HashState();
			s_own_hashes[(f / HASH_INTERVAL) % HASH_HISTORY] = {f, s_last_hash};
			CompareHashes(f);
		}

		// 3. Send, then wait for the peer's input for this frame.
		Send();
		const Clock::time_point start = Clock::now();
		Clock::time_point last_send = start;
		bool warned = false;
		Receive();
		while (!HaveRemote(f))
		{
			pollfd pfd = {s_socket, POLLIN, 0};
			poll(&pfd, 1, 2);
			Receive();

			const Clock::time_point now = Clock::now();
			if (now - last_send > std::chrono::milliseconds(16))
			{
				Send(); // keep the peer fed in case our last packet was lost
				last_send = now;
			}
			if (!warned && now - start > std::chrono::seconds(3))
			{
				warned = true;
				Log("waiting for peer at frame %lld...", static_cast<long long>(f));
			}
			if (now - start > std::chrono::seconds(30))
			{
				Log("peer lost at frame %lld; netplay stopped", static_cast<long long>(f));
				s_active = false;
				return;
			}
		}
		const double waited_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
		s_wait_total_ms += waited_ms;
		s_wait_max_ms = std::max(s_wait_max_ms, waited_ms);
		if (waited_ms > 1.0)
			s_stalled_frames++;

		// 4. Both machines apply the same inputs: host on port 1, guest on port 2.
		const Input& ours = InputFor(s_local, f);
		const Input& theirs = InputFor(s_remote, f);
		Apply(0, s_is_host ? ours : theirs);
		Apply(1, s_is_host ? theirs : ours);

		if (f > 0 && f % 60 == 0)
		{
			Log("frame %lld: wait avg %.2f ms max %.1f ms, %u/60 frames stalled >1ms, sent %u recv %u, "
				"hash checks ok %u, desyncs %u, state %016llx",
				static_cast<long long>(f), s_wait_total_ms / 60.0, s_wait_max_ms, s_stalled_frames, s_sent, s_received,
				s_hash_ok, s_desyncs, static_cast<unsigned long long>(s_last_hash));
			s_wait_total_ms = s_wait_max_ms = 0;
			s_stalled_frames = s_sent = s_received = 0;
		}

		s_frame++;
		if (s_frames_to_run && static_cast<u64>(s_frame) >= s_frames_to_run)
		{
			// Let the peer reach the end too before we disappear.
			for (int i = 0; i < 20 + static_cast<int>(s_latency_ms / 10); i++)
			{
				Send();
				SleepMs(10);
			}
			Log("done: %lld frames, hash checks ok %u, desyncs %u", static_cast<long long>(s_frame), s_hash_ok, s_desyncs);
			std::fclose(s_log);
			std::_Exit(0);
		}
	}
} // namespace Netplay
