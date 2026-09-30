// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "Netplay.h"

#include "BuildVersion.h"
#include "Config.h"
#include "Host.h"
#include "IopMem.h"
#include "Memory.h"
#include "SIO/Pad/Pad.h"
#include "SIO/Pad/PadDualshock2.h"
#include "SaveState.h"
#include "VMManager.h"
#include "VUmicro.h"

#include "common/Console.h"
#include "common/Error.h"
#include "common/FileSystem.h"
#include "common/Path.h"

#define XXH_STATIC_LINKING_ONLY 1
#define XXH_INLINE_ALL 1
#include "xxhash.h"

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#ifndef SIO_UDP_CONNRESET // hidden by some _WIN32_WINNT settings
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
using socket_t = SOCKET;
static constexpr socket_t BAD_SOCKET = INVALID_SOCKET;
#define poll WSAPoll
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
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
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <random>
#include <thread>
#include <string>
#include <type_traits>
#include <vector>

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
	/// Bump whenever the wire format or the lockstep rules change.
	static constexpr u8 PROTOCOL_VERSION = 3;
	static constexpr u32 MAX_DELAY = 30;
	static constexpr double FRAME_MS = 1000.0 / 59.94;
	/// Round-trip samples the host takes during the handshake before it picks
	/// the starting delay.
	static constexpr u32 HANDSHAKE_RTT_SAMPLES = 10;
	static constexpr auto HELLO_INTERVAL = std::chrono::milliseconds(50);

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

	enum PacketType : u8
	{
		PACKET_HELLO = 1,
		PACKET_INPUT = 2,
		PACKET_STATE_CHUNK = 3,
		PACKET_STATE_ACK = 4,
	};

	/// Save-state transfer: chunks small enough for one UDP packet on any
	/// path (with the relay header), and how many may be in flight.
	static constexpr u32 STATE_CHUNK_SIZE = 1200;
	static constexpr u32 STATE_WINDOW = 512;
	static constexpr u32 MAX_STATE_SIZE = 128 * 1024 * 1024;

#pragma pack(push, 1)
	// Wire format. Every supported host is little-endian, and the handshake
	// only lets identical builds play each other, so structs are sent as-is.

	struct Header
	{
		u32 magic;
		u8 type;
		u8 protocol;
		u16 reserved;
		/// Sender's clock in microseconds (never 0), plus the newest peer clock
		/// it has received and how long it held it, so either side can measure
		/// the round-trip time from any packet.
		u32 send_us;
		u32 echo_us;
		u32 echo_hold_us;
	};

	/// Everything that must match for two machines to emulate identically.
	/// The settings are hashed per group so a mismatch can say which group.
	struct SessionInfo
	{
		char build[48];
		char arch[8];
		char serial[16];
		u32 disc_crc;
		u64 bios;
		u64 cpu;
		u64 hacks;
		u64 patches;
		u64 rtc;
		u64 renderer;
		u64 pads;
		u64 memcards;
	};

	struct HelloPacket
	{
		Header header;
		u8 is_host;
		/// Host: `delay` is the chosen starting delay. Guest: it accepted it.
		u8 ready;
		u8 delay;
		/// Host: bit 0 = both players start from the host's save state, which
		/// is `state_size` bytes with XXH3 `state_hash`.
		u8 flags;
		u32 state_size;
		u64 state_hash;
		SessionInfo info;
	};

	struct InputPacket
	{
		Header header;
		/// Sender's current input delay. The guest follows the host's.
		u8 delay;
		u8 count;
		u16 reserved;
		s64 newest_frame; // frame of inputs[count - 1]
		s64 hash_frame; // -1 if no hash attached
		u64 hash;
		Input inputs[REDUNDANCY]; // oldest first
	};

	struct StateChunkPacket
	{
		Header header;
		u32 index;
		u16 size;
		u16 reserved;
		u8 data[STATE_CHUNK_SIZE];
	};

	struct StateAckPacket
	{
		Header header;
		/// All chunks before this one have arrived...
		u32 next_needed;
		/// ...plus these after it (bit i = chunk next_needed + 1 + i).
		u64 received[STATE_WINDOW / 64];
		/// The whole state arrived and its hash matched.
		u8 done;
		u8 reserved[3];
	};
#pragma pack(pop)

	static constexpr size_t MAX_PACKET_SIZE =
		std::max({sizeof(HelloPacket), sizeof(InputPacket), sizeof(StateChunkPacket), sizeof(StateAckPacket)});
	using PacketBuffer = std::array<u8, MAX_PACKET_SIZE>;

	static std::once_flag s_init_once;
	static bool s_active = false;
	static bool s_is_host = true;
	static bool s_session_started = false;
	static socket_t s_socket = BAD_SOCKET;
	static sockaddr_in s_peer = {};

	// Lobby (room codes). With ARMSX2_NETPLAY_SERVER and _ROOM instead of
	// _PEER, the lobby tells each player the other's public and LAN address.
	// Both send to all of them at once (UDP hole punching) and keep the first
	// that answers; if none does, they relay through the lobby. The lobby is
	// contacted from the game socket so the NAT mapping it sees is the one the
	// peer must reach.
	enum class Route : u8
	{
		Direct, // to s_peer
		Probing, // to every candidate address of the peer
		Relay, // through the lobby
	};
	static constexpr size_t RELAY_HEADER_SIZE = 16; // "NPR1", side, 3 zero bytes, token (u64 LE)
	static constexpr auto PROBE_TIMEOUT = std::chrono::seconds(3);
	static std::atomic<Route> s_route{Route::Direct};
	static bool s_use_lobby = false;
	static bool s_force_relay = false;
	static sockaddr_in s_lobby = {};
	static std::string s_room;
	static std::string s_client_id;
	static bool s_lobby_paired = false;
	static std::vector<sockaddr_in> s_candidates;
	static u64 s_relay_token = 0;
	static u8 s_relay_side = 0;
	static std::chrono::steady_clock::time_point s_probe_start;
	static std::FILE* s_log = nullptr;
	static bool s_scripted = false;
	static u32 s_script_seed = 0;
	static u64 s_frames_to_run = 0;
	static u32 s_loss_percent = 0;
	/// Simulated one-way network latency for testing, in milliseconds.
	static u32 s_latency_ms = 0;
	/// Test schedule "frame:ms,frame:ms,...": changes the simulated latency
	/// at those frames, to exercise the adaptive delay.
	static std::vector<std::pair<s64, u32>> s_latency_plan;

	// Input delay. Local input sampled at frame f is used at frame f + delay.
	// The host chooses the delay (fixed, or adapted to the measured round-trip
	// time) and the guest follows it. Because every input is tagged with its
	// frame, a change never desyncs: raising the delay repeats the current
	// input for the skipped frames, lowering it records nothing until frame
	// f + delay passes the newest recorded one.
	static bool s_fixed_delay = false;
	static u32 s_delay = 3;
	/// Delay both sides started with. Frames before it are neutral by definition.
	static u32 s_start_delay = 3;
	static u32 s_min_delay = 2;
	static u32 s_max_delay = 15;
	static s64 s_last_recorded = -1;
	/// Frame of the host packet the guest last took the delay from.
	static s64 s_delay_source_frame = -1;
	/// Host: consecutive seconds the round-trip time allowed a lower delay.
	static u32 s_lower_streak = 0;
	/// Host: a delay raised because of stalls is kept at least until this frame.
	static u32 s_stall_floor = 0;
	static s64 s_stall_floor_until = -1;
	/// When the current 60-frame stretch began, to spot real slowdowns.
	static Clock::time_point s_second_start;
	/// Frame of the last delay rise: the slowdown that caused it isn't jitter.
	/// 0 also ignores the first 2 s, which include the start-up (and any load).
	static s64 s_last_rise_frame = 0;

	// Round-trip time. Packets are only read once per frame, so a sample can
	// include up to a frame of waiting in our socket; the minimum over the last
	// few seconds doesn't, so the delay is based on that. The smoothed value
	// (like TCP, RFC 6298) is for the log.
	static const Clock::time_point s_epoch = Clock::now();
	static u32 s_peer_send_us = 0;
	static Clock::time_point s_peer_send_seen;
	static double s_srtt_ms = 0;
	static double s_rttvar_ms = 0;
	static u32 s_rtt_samples = 0;
	static constexpr double NO_SAMPLE = 1e9;
	/// Minimum per second: the current one and the two before it.
	static std::array<double, 3> s_rtt_min_ms = {NO_SAMPLE, NO_SAMPLE, NO_SAMPLE};

	// Handshake state.
	static SessionInfo s_info = {};
	static bool s_peer_checked = false;
	static bool s_host_ready = false; // host: starting delay chosen / guest: host's choice received
	static bool s_peer_ready = false; // host: guest accepted
	static u32 s_host_delay = 0; // guest: the host's starting delay
	static bool s_peer_sent_input = false;

	// Starting from a save state (ARMSX2_NETPLAY_STATE on the host): after the
	// handshake the host sends the state file, then both load it at the same
	// vsync (the host too: a loaded state isn't bit-identical to the game that
	// saved it, but two loads of one state are) and lockstep starts from there.
	enum class StatePhase : u8
	{
		None, // start from power-on
		Transfer, // send / receive the state at the next vsync
		Done,
	};
	static StatePhase s_state_phase = StatePhase::None;
	static std::string s_state_path; // host: the file; guest: where it's written
	static std::vector<u8> s_state_data;
	static u32 s_state_size = 0;
	static u64 s_state_hash = 0;
	static u32 s_state_chunks = 0;
	static std::vector<bool> s_state_have; // guest: received / host: acked
	static u32 s_state_have_count = 0;
	static bool s_state_complete = false; // guest: all chunks in and hash OK / host: guest said so
	static Clock::time_point s_state_last_ack;

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

	// Stats, reset every log interval.
	static u32 s_sent = 0, s_received = 0, s_stalled_frames = 0;
	static double s_wait_total_ms = 0, s_wait_max_ms = 0;
	static u32 s_hash_ok = 0, s_desyncs = 0;

	static void SleepMs(int ms)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(ms));
	}

	static u32 NowUs()
	{
		const auto us = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - s_epoch).count();
		return static_cast<u32>(us) | 1u; // 0 means "nothing to echo"
	}

	static void SendRaw(const sockaddr_in& to, const void* data, size_t size)
	{
		sendto(s_socket, reinterpret_cast<const char*>(data), static_cast<int>(size), 0,
			reinterpret_cast<const sockaddr*>(&to), sizeof(to));
	}

	/// Sends a game packet along the current route. Also called from the
	/// latency simulation thread.
	static void SendTo(const void* data, size_t size)
	{
		switch (s_route.load(std::memory_order_acquire))
		{
			case Route::Direct:
				SendRaw(s_peer, data, size);
				break;
			case Route::Probing:
				for (const sockaddr_in& candidate : s_candidates)
					SendRaw(candidate, data, size);
				break;
			case Route::Relay:
			{
				std::array<u8, RELAY_HEADER_SIZE + MAX_PACKET_SIZE> buffer;
				if (RELAY_HEADER_SIZE + size > buffer.size())
					break;
				std::memcpy(buffer.data(), "NPR1", 4);
				buffer[4] = s_relay_side;
				buffer[5] = buffer[6] = buffer[7] = 0;
				for (int i = 0; i < 8; i++)
					buffer[8 + i] = static_cast<u8>(s_relay_token >> (8 * i));
				std::memcpy(buffer.data() + RELAY_HEADER_SIZE, data, size);
				SendRaw(s_lobby, buffer.data(), RELAY_HEADER_SIZE + size);
				break;
			}
		}
	}

	static std::string AddressText(const sockaddr_in& addr)
	{
		char ip[INET_ADDRSTRLEN] = {};
		inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
		return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
	}

	static bool SameAddress(const sockaddr_in& a, const sockaddr_in& b)
	{
		return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
	}

	/// Parses "ip:port" or, if `resolve`, "hostname:port".
	static bool ParseAddress(std::string_view text, sockaddr_in* out, bool resolve = false)
	{
		const size_t colon = text.rfind(':');
		if (colon == std::string_view::npos)
			return false;
		const std::string host(text.substr(0, colon));
		const std::string port(text.substr(colon + 1));
		*out = {};
		out->sin_family = AF_INET;
		out->sin_port = htons(static_cast<u16>(std::strtoul(port.c_str(), nullptr, 10)));
		if (inet_pton(AF_INET, host.c_str(), &out->sin_addr) == 1)
			return true;
		if (!resolve)
			return false;
		addrinfo hints = {};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		addrinfo* result = nullptr;
		if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result)
			return false;
		out->sin_addr = reinterpret_cast<const sockaddr_in*>(result->ai_addr)->sin_addr;
		freeaddrinfo(result);
		return true;
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

	static bool VMStopping()
	{
		const VMState state = VMManager::GetState();
		return state == VMState::Stopping || state == VMState::Shutdown;
	}

	static void Initialize()
	{
		const char* mode = std::getenv("ARMSX2_NETPLAY");
		if (!mode || (std::strcmp(mode, "host") != 0 && std::strcmp(mode, "join") != 0))
			return;
		s_is_host = std::strcmp(mode, "host") == 0;

		if (const char* path = std::getenv("ARMSX2_NETPLAY_LOG"))
			s_log = std::fopen(path, "w");
		if (const char* v = std::getenv("ARMSX2_NETPLAY_MIN_DELAY"))
			s_min_delay = std::clamp<u32>(static_cast<u32>(std::strtoul(v, nullptr, 10)), 1, MAX_DELAY);
		if (const char* v = std::getenv("ARMSX2_NETPLAY_MAX_DELAY"))
			s_max_delay = std::clamp<u32>(static_cast<u32>(std::strtoul(v, nullptr, 10)), s_min_delay, MAX_DELAY);
		if (const char* v = std::getenv("ARMSX2_NETPLAY_DELAY"); v && *v && std::strcmp(v, "auto") != 0)
		{
			s_fixed_delay = true;
			s_delay = std::clamp<u32>(static_cast<u32>(std::strtoul(v, nullptr, 10)), 1, MAX_DELAY);
		}
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
		if (const char* v = std::getenv("ARMSX2_NETPLAY_STATE"); v && *v)
		{
			if (s_is_host)
				s_state_path = v;
			else
				Log("note: ARMSX2_NETPLAY_STATE is ignored for the guest; the host's state is used");
		}
		if (const char* v = std::getenv("ARMSX2_NETPLAY_LATENCY_PLAN"))
		{
			for (const char* p = v; *p;)
			{
				char* end;
				const s64 frame = std::strtoll(p, &end, 10);
				if (*end != ':')
					break;
				const u32 ms = std::min<u32>(static_cast<u32>(std::strtoul(end + 1, &end, 10)), 1000);
				s_latency_plan.emplace_back(frame, ms);
				p = *end == ',' ? end + 1 : end;
			}
		}

		const u16 port = static_cast<u16>(std::strtoul(
			std::getenv("ARMSX2_NETPLAY_PORT") ? std::getenv("ARMSX2_NETPLAY_PORT") : (s_is_host ? "7777" : "7778"),
			nullptr, 10));

#ifdef _WIN32
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

		std::string peer_text;
		const char* server = std::getenv("ARMSX2_NETPLAY_SERVER");
		const char* room = std::getenv("ARMSX2_NETPLAY_ROOM");
		if (server && *server && room && *room)
		{
			if (!ParseAddress(server, &s_lobby, true))
			{
				Log("error: can't resolve the lobby server %s (use host:port)", server);
				return;
			}
			s_use_lobby = true;
			s_room = room;
			s_force_relay = std::getenv("ARMSX2_NETPLAY_FORCE_RELAY") != nullptr;
			std::random_device random;
			char id[17];
			std::snprintf(id, sizeof(id), "%08x%08x", random(), random());
			s_client_id = id;
			peer_text = "room " + s_room + " via lobby " + AddressText(s_lobby);
		}
		else
		{
			const char* peer = std::getenv("ARMSX2_NETPLAY_PEER");
			if (!peer || !ParseAddress(peer, &s_peer))
			{
				Log("error: set ARMSX2_NETPLAY_PEER=ip:port, or ARMSX2_NETPLAY_SERVER=host:port and ARMSX2_NETPLAY_ROOM");
				return;
			}
			peer_text = "peer " + AddressText(s_peer);
		}
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
		// Room for a burst of save-state chunks (the default can be 64 KB).
		const int buffer_size = 4 * 1024 * 1024;
		setsockopt(s_socket, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size));
		setsockopt(s_socket, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buffer_size), sizeof(buffer_size));
#ifdef _WIN32
		u_long nonblocking = 1;
		ioctlsocket(s_socket, FIONBIO, &nonblocking);
		// Otherwise a probe to an address nobody listens on makes the next
		// recvfrom() fail with WSAECONNRESET.
		BOOL report_reset = FALSE;
		DWORD bytes = 0;
		WSAIoctl(s_socket, SIO_UDP_CONNRESET, &report_reset, sizeof(report_reset), nullptr, 0, &bytes, nullptr, nullptr);
#else
		fcntl(s_socket, F_SETFL, fcntl(s_socket, F_GETFL, 0) | O_NONBLOCK);
#endif

		s_active = true;
		const char* peer = peer_text.c_str();
		if (!s_is_host)
			Log("netplay guest (player 2), port %u, %s%s; the host chooses the input delay", port, peer,
				s_scripted ? ", scripted input" : "");
		else if (s_fixed_delay)
			Log("netplay host (player 1), port %u, %s, fixed delay %u frames%s", port, peer, s_delay,
				s_scripted ? ", scripted input" : "");
		else
			Log("netplay host (player 1), port %u, %s, adaptive delay %u-%u frames%s", port, peer, s_min_delay,
				s_max_delay, s_scripted ? ", scripted input" : "");
	}

	bool CaptureLocalInput(u32 controller, u32 bind, float value)
	{
		// Input can arrive on another thread before the first vsync.
		std::call_once(s_init_once, Initialize);
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

	// ------------------------------------------------------------------------
	// Session info
	// ------------------------------------------------------------------------

	/// Collects plain values and hashes them. Values are copied, so bit-fields work.
	class Fingerprint
	{
	public:
		template <typename T>
		Fingerprint& Add(T value)
		{
			static_assert(std::is_arithmetic_v<T> || std::is_enum_v<T>);
			const u8* bytes = reinterpret_cast<const u8*>(&value);
			m_bytes.insert(m_bytes.end(), bytes, bytes + sizeof(T));
			return *this;
		}

		Fingerprint& Add(const FPControlRegister& fpcr)
		{
			// The raw register differs between x86 and ARM; compare what it means.
			return Add(fpcr.GetRoundMode()).Add(fpcr.GetDenormalsAreZero()).Add(fpcr.GetFlushToZero());
		}

		u64 Hash() const { return XXH3_64bits(m_bytes.data(), m_bytes.size()); }

	private:
		std::vector<u8> m_bytes;
	};

	static void CopyString(char* dst, size_t size, std::string_view src)
	{
		std::memset(dst, 0, size);
		std::memcpy(dst, src.data(), std::min(size - 1, src.size()));
	}

	static void ComputeSessionInfo()
	{
		SessionInfo& info = s_info;
		CopyString(info.build, sizeof(info.build), BuildVersion::GitHash);
#if defined(ARCH_X86)
		CopyString(info.arch, sizeof(info.arch), "x86-64");
#elif defined(ARCH_ARM64)
		CopyString(info.arch, sizeof(info.arch), "arm64");
#else
		CopyString(info.arch, sizeof(info.arch), "unknown");
#endif
		CopyString(info.serial, sizeof(info.serial), VMManager::GetDiscSerial());
		info.disc_crc = VMManager::GetDiscCRC();
		info.bios = XXH3_64bits(eeMem->ROM, sizeof(eeMem->ROM));

		const Pcsx2Config& c = EmuConfig;
		info.cpu = Fingerprint()
					   .Add(c.Cpu.bitset)
					   .Add(c.Cpu.Recompiler.bitset)
					   .Add(c.Cpu.FPUFPCR)
					   .Add(c.Cpu.FPUDivFPCR)
					   .Add(c.Cpu.VU0FPCR)
					   .Add(c.Cpu.VU1FPCR)
					   .Hash();
		info.hacks = Fingerprint()
						 .Add(c.Speedhacks.bitset)
						 .Add(c.Speedhacks.EECycleRate)
						 .Add(c.Speedhacks.EECycleSkip)
						 .Add(c.Gamefixes.bitset)
						 .Add(static_cast<bool>(c.EnableGameFixes))
						 .Hash();
		info.patches = Fingerprint()
						   .Add(static_cast<bool>(c.EnablePatches))
						   .Add(static_cast<bool>(c.EnableCheats))
						   .Add(static_cast<bool>(c.EnableWideScreenPatches))
						   .Add(static_cast<bool>(c.EnableNoInterlacingPatches))
						   .Add(static_cast<bool>(c.EnableFastBoot))
						   .Add(static_cast<bool>(c.HostFs))
						   .Hash();
		info.rtc = Fingerprint()
					   .Add(static_cast<bool>(c.ManuallySetRealTimeClock))
					   .Add(c.RtcYear)
					   .Add(c.RtcMonth)
					   .Add(c.RtcDay)
					   .Add(c.RtcHour)
					   .Add(c.RtcMinute)
					   .Add(c.RtcSecond)
					   .Hash();
		// The renderer changes GS readbacks into EE memory. Upscaling only
		// matters for the hardware renderers.
		Fingerprint renderer;
		renderer.Add(c.GS.Renderer);
		if (c.GS.Renderer != GSRendererType::SW)
			renderer.Add(c.GS.UpscaleMultiplier);
		info.renderer = renderer.Hash();

		Fingerprint pads;
		for (const auto& port : c.Pad.Ports)
			pads.Add(port.Type);
		info.pads = pads.Add(c.Pad.bitset).Hash();

		// Games read saves (and settings) from the cards, so their contents count.
		Fingerprint cards;
		for (u32 slot = 0; slot < std::size(c.Mcd); slot++)
		{
			cards.Add(c.Mcd[slot].Enabled).Add(c.Mcd[slot].Type);
			if (!c.Mcd[slot].Enabled || c.Mcd[slot].Type != MemoryCardType::File)
				continue;
			// The emulator has the card open for writing; a plain open would
			// fail on Windows, so allow sharing.
			const std::string path = c.FullpathToMcd(slot);
			std::optional<std::vector<u8>> data;
			if (FileSystem::ManagedCFilePtr fp = FileSystem::OpenManagedSharedCFile(
					path.c_str(), "rb", FileSystem::FileShareMode::DenyNone))
			{
				data = FileSystem::ReadBinaryFile(fp.get());
			}
			if (!data.has_value())
				Log("warning: can't read memory card %s; it won't be compared", path.c_str());
			cards.Add(data.has_value() ? XXH3_64bits(data->data(), data->size()) : u64{0});
		}
		info.memcards = cards.Hash();
	}

	/// Settings that can't work in netplay at all, whatever the peer uses.
	static std::vector<std::string> LocalProblems()
	{
		std::vector<std::string> problems;
		if (!EmuConfig.ManuallySetRealTimeClock)
			problems.push_back("the real-time clock must be set manually (the same date and time on both machines)");
		for (u32 port = 0; port < 2; port++)
		{
			if (EmuConfig.Pad.Ports[port].Type != Pad::ControllerType::DualShock2)
				problems.push_back("controller port " + std::to_string(port + 1) + " must be a DualShock 2");
		}
		for (u32 slot = 0; slot < std::size(EmuConfig.Mcd); slot++)
		{
			if (EmuConfig.Mcd[slot].Enabled && EmuConfig.Mcd[slot].Type == MemoryCardType::Folder)
				problems.push_back("folder memory cards can't be compared; use file memory cards");
		}
		return problems;
	}

	static std::vector<std::string> CompareSessionInfo(const HelloPacket& peer)
	{
		std::vector<std::string> problems;
		const SessionInfo& ours = s_info;
		const SessionInfo& theirs = peer.info;
		auto text = [](const char* s, size_t size) { return std::string(s, strnlen(s, size)); };

		if (static_cast<bool>(peer.is_host) == s_is_host)
			problems.push_back(s_is_host ? "both players are set to host" : "both players are set to join");
		if (std::memcmp(ours.arch, theirs.arch, sizeof(ours.arch)) != 0)
			problems.push_back("different CPU architectures (" + text(ours.arch, sizeof(ours.arch)) + " vs " +
							   text(theirs.arch, sizeof(theirs.arch)) + "): their emulation timing differs");
		if (std::memcmp(ours.build, theirs.build, sizeof(ours.build)) != 0)
			problems.push_back("different emulator builds (" + text(ours.build, sizeof(ours.build)) + " vs " +
							   text(theirs.build, sizeof(theirs.build)) + ")");
		if (std::memcmp(ours.serial, theirs.serial, sizeof(ours.serial)) != 0 || ours.disc_crc != theirs.disc_crc)
		{
			char buf[128];
			std::snprintf(buf, sizeof(buf), "different games (%s %08X vs %s %08X)", text(ours.serial, sizeof(ours.serial)).c_str(),
				ours.disc_crc, text(theirs.serial, sizeof(theirs.serial)).c_str(), theirs.disc_crc);
			problems.push_back(buf);
		}
		if (ours.bios != theirs.bios)
			problems.push_back("different BIOS files");
		if (ours.cpu != theirs.cpu)
			problems.push_back("different CPU settings (recompilers, rounding or clamping modes)");
		if (ours.hacks != theirs.hacks)
			problems.push_back("different speed hacks or game fixes");
		if (ours.patches != theirs.patches)
			problems.push_back("different patch, cheat or fast boot settings");
		if (ours.rtc != theirs.rtc)
			problems.push_back("different real-time clock settings");
		if (ours.renderer != theirs.renderer)
			problems.push_back("different renderers (or upscaling with a hardware renderer)");
		if (ours.pads != theirs.pads)
			problems.push_back("different controller types or multitap settings");
		if (ours.memcards != theirs.memcards)
			problems.push_back("different memory cards (contents or settings)");
		return problems;
	}

	// ------------------------------------------------------------------------
	// Round-trip time and delay
	// ------------------------------------------------------------------------

	static void AddRttSample(double rtt_ms)
	{
		s_rtt_min_ms[0] = std::min(s_rtt_min_ms[0], rtt_ms);
		if (s_rtt_samples++ == 0)
		{
			s_srtt_ms = rtt_ms;
			s_rttvar_ms = rtt_ms / 4;
			return;
		}
		s_rttvar_ms = 0.75 * s_rttvar_ms + 0.25 * std::abs(s_srtt_ms - rtt_ms);
		s_srtt_ms = 0.875 * s_srtt_ms + 0.125 * rtt_ms;
	}

	/// Called once per second: start a new minimum bucket.
	static void RotateRttWindow()
	{
		if (s_rtt_min_ms[0] == NO_SAMPLE)
			return; // nothing measured this second; keep the old buckets
		for (size_t i = s_rtt_min_ms.size() - 1; i > 0; i--)
			s_rtt_min_ms[i] = s_rtt_min_ms[i - 1];
		s_rtt_min_ms[0] = NO_SAMPLE;
	}

	static double RoundTripMs()
	{
		const double rtt = *std::min_element(s_rtt_min_ms.begin(), s_rtt_min_ms.end());
		return rtt == NO_SAMPLE ? s_srtt_ms : rtt;
	}

	/// Length of one emulated frame (NTSC 16.7 ms, PAL 20 ms).
	static double FrameMs()
	{
		const float hz = VMManager::GetFrameRate();
		return hz > 1.0f ? 1000.0 / hz : FRAME_MS;
	}

	/// Delay that covers the one-way latency plus a little slack for frame
	/// pacing. Matches the Mac measurements: 40 ms one way -> 3 frames,
	/// 80 ms -> 6. Jitter is handled by AdaptDelay() watching for slowdowns.
	static u32 DelayForRtt(double rtt_ms)
	{
		const double needed_ms = rtt_ms / 2 + 4.0;
		const u32 frames = static_cast<u32>(std::ceil(needed_ms / FrameMs()));
		return std::clamp(frames, s_min_delay, s_max_delay);
	}

	static u32 DelayForRtt()
	{
		return DelayForRtt(RoundTripMs());
	}

	static void SetDelay(u32 delay, const char* reason)
	{
		if (delay == s_delay)
			return;
		Log("frame %lld: delay %u -> %u (%s; rtt %.1f ms, min %.1f ms)", static_cast<long long>(s_frame), s_delay,
			delay, reason, s_srtt_ms, RoundTripMs());
		s_delay = delay;
	}

	/// Host, once per second (`second_ms` = how long the last 60 frames took):
	/// follow the round-trip time. Rises are judged on the last second alone,
	/// so they happen at once; falls on the minimum of the last 3 seconds and
	/// only after 3 calm seconds, then one frame per second, so a brief dip
	/// doesn't make the delay jump around.
	static void AdaptDelay(double second_ms)
	{
		if (!s_is_host || s_fixed_delay || s_rtt_samples == 0)
			return;

		const u32 up = DelayForRtt(s_rtt_min_ms[0] == NO_SAMPLE ? RoundTripMs() : s_rtt_min_ms[0]);
		const u32 down = DelayForRtt();

		// The game really slowed down although the delay covers the round
		// trip: jitter or uneven frame pacing. Lockstep slows both peers alike,
		// so the host sees it for both. Allow up to 2 frames extra, and keep
		// that for 10 seconds before trusting the round-trip time again. (A PC
		// too slow for the game also lands here; the cap keeps that harmless.)
		const bool slowed = second_ms > 60 * FrameMs() * 1.03 && s_frame - s_last_rise_frame > 120;
		if (slowed && s_delay >= up && s_delay < std::min(up + 2, s_max_delay))
		{
			s_stall_floor = s_delay + 1;
			s_stall_floor_until = s_frame + 600;
		}
		const u32 stall_floor = s_frame < s_stall_floor_until ? s_stall_floor : 0;

		if (std::max(up, stall_floor) > s_delay)
		{
			s_lower_streak = 0;
			s_last_rise_frame = s_frame;
			SetDelay(std::max(up, stall_floor), stall_floor > up ? "game slowed down" : "latency rose");
		}
		else if (std::max(down, stall_floor) < s_delay)
		{
			if (++s_lower_streak >= 3)
				SetDelay(s_delay - 1, "latency fell");
		}
		else
		{
			s_lower_streak = 0;
		}
	}

	// ------------------------------------------------------------------------
	// Sending
	// ------------------------------------------------------------------------

	/// Packets held back to simulate latency. A dedicated thread sends each one
	/// exactly when due, independent of the emulator's frame timing.
	struct Outgoing
	{
		Clock::time_point due;
		PacketBuffer data;
		size_t size;
	};
	static std::deque<Outgoing> s_outgoing;
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
			const Clock::time_point due = s_outgoing.front().due;
			if (Clock::now() < due)
			{
				s_outgoing_cv.wait_until(lock, due);
				continue;
			}
			const Outgoing packet = s_outgoing.front();
			s_outgoing.pop_front();
			lock.unlock();
			SendTo(packet.data.data(), packet.size);
			lock.lock();
		}
	}

	static void FillHeader(Header& header, PacketType type)
	{
		header.magic = MAGIC;
		header.type = type;
		header.protocol = PROTOCOL_VERSION;
		header.reserved = 0;
		header.send_us = NowUs();
		header.echo_us = s_peer_send_us;
		header.echo_hold_us = s_peer_send_us ? static_cast<u32>(std::chrono::duration_cast<std::chrono::microseconds>(
													 Clock::now() - s_peer_send_seen).count()) :
		                                       0;
	}

	/// Sends with the simulated loss and latency applied.
	static void SendPacket(const void* data, size_t size)
	{
		s_sent++;
		if (s_loss_percent && static_cast<u32>(std::rand() % 100) < s_loss_percent)
			return; // simulated loss
		if (s_latency_ms == 0)
		{
			SendTo(data, size);
			return;
		}
		if (!s_latency_thread_started)
		{
			s_latency_thread_started = true;
			std::thread(LatencyThread).detach();
		}
		{
			Outgoing packet;
			packet.due = Clock::now() + std::chrono::milliseconds(s_latency_ms);
			std::memcpy(packet.data.data(), data, size);
			packet.size = size;
			std::lock_guard lock(s_outgoing_mutex);
			s_outgoing.push_back(packet);
		}
		s_outgoing_cv.notify_one();
	}

	static void SendHello()
	{
		HelloPacket packet = {};
		FillHeader(packet.header, PACKET_HELLO);
		packet.is_host = s_is_host;
		packet.ready = s_is_host ? s_host_ready : s_session_started;
		packet.delay = static_cast<u8>(s_is_host ? s_start_delay : s_host_delay);
		if (s_is_host && !s_state_path.empty())
		{
			packet.flags = 1;
			packet.state_size = s_state_size;
			packet.state_hash = s_state_hash;
		}
		packet.info = s_info;
		SendPacket(&packet, sizeof(packet));
	}

	static void SendInput()
	{
		InputPacket packet = {};
		FillHeader(packet.header, PACKET_INPUT);
		packet.delay = static_cast<u8>(s_delay);
		const s64 newest = s_last_recorded;
		packet.newest_frame = newest;
		// Inputs exist from the starting delay on; earlier frames are neutral.
		const s64 available = newest - static_cast<s64>(s_start_delay) + 1;
		packet.count = static_cast<u8>(std::clamp<s64>(available, 0, REDUNDANCY));
		for (u32 i = 0; i < packet.count; i++)
		{
			const s64 frame = newest - packet.count + 1 + i;
			packet.inputs[i] = s_local[frame % HISTORY].input;
		}
		packet.hash_frame = s_last_hash_frame;
		packet.hash = s_last_hash;
		SendPacket(&packet, sizeof(packet));
	}

	// ------------------------------------------------------------------------
	// Receiving
	// ------------------------------------------------------------------------

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

	static void OnHeader(const Header& header)
	{
		s_peer_send_us = header.send_us;
		s_peer_send_seen = Clock::now();
		if (header.echo_us == 0)
			return;
		// Unsigned arithmetic handles the 32-bit clock wrapping.
		const u32 rtt_us = NowUs() - header.echo_us - header.echo_hold_us;
		if (rtt_us < 2'000'000)
			AddRttSample(rtt_us / 1000.0);
	}

	[[noreturn]] static void FailSession(const std::vector<std::string>& problems)
	{
		Log("error: can't start netplay:");
		for (const std::string& problem : problems)
		{
			Log("  - %s", problem.c_str());
			Console.Error("Netplay: %s", problem.c_str());
		}
		// Make sure the peer gets our details so it can report the problem too.
		for (int i = 0; i < 10; i++)
		{
			SendHello();
			SleepMs(20);
		}
		if (s_log)
			std::fclose(s_log);
		std::_Exit(3);
	}

	static void OnHello(const HelloPacket& packet)
	{
		if (s_session_started)
			return; // a late duplicate from the handshake

		if (!s_peer_checked)
		{
			const std::vector<std::string> problems = CompareSessionInfo(packet);
			if (!problems.empty())
				FailSession(problems);
			s_peer_checked = true;
			Log("peer found: same build, game %s (%08X), BIOS and settings", s_info.serial, s_info.disc_crc);
		}

		if (packet.ready)
		{
			if (s_is_host)
			{
				s_peer_ready = true;
			}
			else if (!s_host_ready)
			{
				s_host_ready = true;
				s_host_delay = std::clamp<u32>(packet.delay, 1, MAX_DELAY);
				if (packet.flags & 1)
				{
					if (packet.state_size == 0 || packet.state_size > MAX_STATE_SIZE)
						FailSession({"the host's save state is too large"});
					s_state_size = packet.state_size;
					s_state_hash = packet.state_hash;
					s_state_phase = StatePhase::Transfer;
				}
			}
		}
	}

	static void OnInput(const InputPacket& packet)
	{
		if (packet.count > REDUNDANCY)
			return;
		s_peer_sent_input = true;

		for (u32 i = 0; i < packet.count; i++)
		{
			const s64 frame = packet.newest_frame - packet.count + 1 + i;
			InputSlot& slot = s_remote[frame % HISTORY];
			if (frame >= s_frame && frame < s_frame + static_cast<s64>(HISTORY) && slot.frame < frame)
			{
				slot.frame = frame;
				slot.input = packet.inputs[i];
			}
		}

		// The guest follows the host's delay, from the newest packet only so a
		// reordered old packet can't undo a change.
		if (!s_is_host && s_session_started && packet.newest_frame > s_delay_source_frame)
		{
			s_delay_source_frame = packet.newest_frame;
			if (packet.delay >= 1 && packet.delay <= MAX_DELAY && packet.delay != s_delay)
				SetDelay(packet.delay, "set by host");
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

	// ------------------------------------------------------------------------
	// Save-state transfer packets
	// ------------------------------------------------------------------------

	/// Guest: tells the host which chunks have arrived.
	static void SendStateAck()
	{
		StateAckPacket ack = {};
		FillHeader(ack.header, PACKET_STATE_ACK);
		u32 next = 0;
		while (next < s_state_chunks && s_state_have[next])
			next++;
		ack.next_needed = next;
		for (u32 i = 0; i < STATE_WINDOW; i++)
		{
			const u32 chunk = next + 1 + i;
			if (chunk < s_state_chunks && s_state_have[chunk])
				ack.received[i / 64] |= u64{1} << (i % 64);
		}
		ack.done = s_state_complete;
		SendPacket(&ack, sizeof(ack));
		s_state_last_ack = Clock::now();
	}

	static void OnStateChunk(const StateChunkPacket& packet)
	{
		if (s_is_host || s_state_chunks == 0)
			return;
		if (s_state_complete)
		{
			SendStateAck(); // the host missed our "done"
			return;
		}
		const u64 offset = u64{packet.index} * STATE_CHUNK_SIZE;
		if (packet.index >= s_state_chunks || packet.size > STATE_CHUNK_SIZE ||
			offset + packet.size != std::min<u64>(offset + STATE_CHUNK_SIZE, s_state_size))
			return;
		if (!s_state_have[packet.index])
		{
			std::memcpy(s_state_data.data() + offset, packet.data, packet.size);
			s_state_have[packet.index] = true;
			s_state_have_count++;
		}
	}

	static void OnStateAck(const StateAckPacket& packet)
	{
		if (!s_is_host || s_state_chunks == 0)
			return;
		if (packet.done)
			s_state_complete = true;
		for (u32 i = 0; i < std::min(packet.next_needed, s_state_chunks); i++)
		{
			if (!s_state_have[i])
			{
				s_state_have[i] = true;
				s_state_have_count++;
			}
		}
		for (u32 i = 0; i < STATE_WINDOW; i++)
		{
			const u32 chunk = packet.next_needed + 1 + i;
			if (chunk < s_state_chunks && (packet.received[i / 64] >> (i % 64) & 1) && !s_state_have[chunk])
			{
				s_state_have[chunk] = true;
				s_state_have_count++;
			}
		}
	}

	// ------------------------------------------------------------------------
	// Lobby
	// ------------------------------------------------------------------------

	/// Registers with the lobby (repeated until it pairs us with the peer).
	static void SendLobbyJoin()
	{
		// Our LAN address: the local end of a route to the lobby. connect() on
		// a UDP socket sends nothing.
		sockaddr_in lan = {};
		const socket_t probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (probe != BAD_SOCKET)
		{
			socklen_t len = sizeof(lan);
			if (connect(probe, reinterpret_cast<const sockaddr*>(&s_lobby), sizeof(s_lobby)) != 0 ||
				getsockname(probe, reinterpret_cast<sockaddr*>(&lan), &len) != 0)
				lan = {};
#ifdef _WIN32
			closesocket(probe);
#else
			close(probe);
#endif
		}
		sockaddr_in bound = {};
		socklen_t bound_len = sizeof(bound);
		getsockname(s_socket, reinterpret_cast<sockaddr*>(&bound), &bound_len);
		lan.sin_family = AF_INET;
		lan.sin_port = bound.sin_port;

		const std::string message = "NPL1 JOIN " + s_room + (s_is_host ? " host " : " join ") + AddressText(lan) + " " +
									std::to_string(PROTOCOL_VERSION) + " " + s_client_id;
		SendRaw(s_lobby, message.data(), message.size());
	}

	static void OnLobbyMessage(std::string_view text)
	{
		std::vector<std::string> words;
		for (size_t pos = 0; pos < text.size();)
		{
			const size_t end = std::min(text.find(' ', pos), text.size());
			if (end > pos)
				words.emplace_back(text.substr(pos, end - pos));
			pos = end + 1;
		}
		if (words.empty())
			return;

		if (words[0] == "WAIT")
		{
			static bool logged = false;
			if (!logged)
				Log("lobby: in room %s, waiting for the other player", s_room.c_str());
			logged = true;
		}
		else if (words[0] == "ERROR" && !s_session_started)
		{
			std::string reason = "the lobby refused to join room " + s_room + ":";
			for (size_t i = 1; i < words.size(); i++)
				reason += " " + words[i];
			FailSession({reason});
		}
		else if (words[0] == "PEER" && words.size() >= 5 && !s_lobby_paired)
		{
			// Addresses are fixed from here on: the latency thread may be
			// reading them. (A peer that restarts gets a new room session.)
			sockaddr_in public_addr, lan_addr;
			if (!ParseAddress(words[1], &public_addr))
				return;
			s_candidates.push_back(public_addr);
			if (ParseAddress(words[2], &lan_addr) && lan_addr.sin_addr.s_addr != 0 && !SameAddress(lan_addr, public_addr))
				s_candidates.push_back(lan_addr);
			s_relay_token = std::strtoull(words[3].c_str(), nullptr, 16);
			s_relay_side = static_cast<u8>(std::strtoul(words[4].c_str(), nullptr, 10));
			s_lobby_paired = true;
			s_probe_start = Clock::now();
			s_route.store(s_force_relay ? Route::Relay : Route::Probing, std::memory_order_release);
			Log("lobby: paired; the other player is at %s (LAN %s)%s", words[1].c_str(), words[2].c_str(),
				s_force_relay ? "; relaying as requested" : "; trying a direct connection");
		}
	}

	/// Falls back to the relay when no direct packet arrived in time.
	static void UpdateRoute()
	{
		if (s_route.load(std::memory_order_relaxed) == Route::Probing && Clock::now() - s_probe_start > PROBE_TIMEOUT)
		{
			s_route.store(Route::Relay, std::memory_order_release);
			Log("no direct path to the other player; relaying through the lobby");
		}
	}

	static void Receive()
	{
		PacketBuffer buffer;
		for (int errors = 0; errors < 64;)
		{
			sockaddr_in from = {};
			socklen_t from_len = sizeof(from);
			const int len = static_cast<int>(recvfrom(s_socket, reinterpret_cast<char*>(buffer.data()),
				static_cast<int>(buffer.size()), 0, reinterpret_cast<sockaddr*>(&from), &from_len));
			if (len < 0)
			{
#ifdef _WIN32
				if (WSAGetLastError() == WSAEWOULDBLOCK)
					break;
#else
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
#endif
				errors++; // e.g. an ICMP "port unreachable" from probing; keep reading
				continue;
			}

			const bool from_lobby = s_use_lobby && SameAddress(from, s_lobby);
			if (from_lobby && len >= 5 && std::memcmp(buffer.data(), "NPL1 ", 5) == 0)
			{
				OnLobbyMessage(std::string_view(reinterpret_cast<const char*>(buffer.data()) + 5, static_cast<size_t>(len) - 5));
				continue;
			}

			if (len < static_cast<int>(sizeof(Header)))
				continue;
			Header header;
			std::memcpy(&header, buffer.data(), sizeof(header));
			if (header.magic != MAGIC)
				continue;
			if (header.protocol != PROTOCOL_VERSION)
			{
				if (!s_session_started)
					FailSession({"the other player runs a different netplay version (protocol " +
								 std::to_string(header.protocol) + ", ours " + std::to_string(PROTOCOL_VERSION) + ")"});
				continue;
			}

			if (s_use_lobby)
			{
				const Route route = s_route.load(std::memory_order_relaxed);
				if (!from_lobby && route != Route::Direct && !s_force_relay)
				{
					// A packet straight from the peer: that path works.
					s_peer = from;
					s_route.store(Route::Direct, std::memory_order_release);
					Log("direct connection to the other player at %s", AddressText(from).c_str());
				}
				else if (from_lobby && route == Route::Probing)
				{
					// The peer gave up on a direct path, so ours doesn't work either.
					s_route.store(Route::Relay, std::memory_order_release);
					Log("the other player is relaying; relaying through the lobby too");
				}
			}

			s_received++;
			OnHeader(header);

			if (header.type == PACKET_HELLO && len == static_cast<int>(sizeof(HelloPacket)))
			{
				HelloPacket packet;
				std::memcpy(&packet, buffer.data(), sizeof(packet));
				OnHello(packet);
			}
			else if (header.type == PACKET_INPUT && len == static_cast<int>(sizeof(InputPacket)))
			{
				InputPacket packet;
				std::memcpy(&packet, buffer.data(), sizeof(packet));
				OnInput(packet);
			}
			else if (header.type == PACKET_STATE_CHUNK && len == static_cast<int>(sizeof(StateChunkPacket)))
			{
				StateChunkPacket packet;
				std::memcpy(&packet, buffer.data(), sizeof(packet));
				OnStateChunk(packet);
			}
			else if (header.type == PACKET_STATE_ACK && len == static_cast<int>(sizeof(StateAckPacket)))
			{
				StateAckPacket packet;
				std::memcpy(&packet, buffer.data(), sizeof(packet));
				OnStateAck(packet);
			}
		}
	}

	// ------------------------------------------------------------------------
	// Handshake
	// ------------------------------------------------------------------------

	/// Runs at the first vsync, before frame 0 is played. Both sides exchange
	/// HELLOs until each has checked the other's session info; the host then
	/// measures the round-trip time, picks the starting delay and sends it,
	/// and both start together. Returns false if the VM is shutting down.
	static bool Handshake()
	{
		ComputeSessionInfo();
		Log("this machine: build %.12s %s, game %s %08X, bios %016llx, cpu %016llx, hacks %016llx, memcards %016llx",
			s_info.build, s_info.arch, s_info.serial, s_info.disc_crc, static_cast<unsigned long long>(s_info.bios),
			static_cast<unsigned long long>(s_info.cpu), static_cast<unsigned long long>(s_info.hacks),
			static_cast<unsigned long long>(s_info.memcards));
		if (const std::vector<std::string> problems = LocalProblems(); !problems.empty())
			FailSession(problems);

		if (!s_state_path.empty())
		{
			std::optional<std::vector<u8>> data = FileSystem::ReadBinaryFile(s_state_path.c_str());
			if (!data.has_value() || data->empty() || data->size() > MAX_STATE_SIZE)
				FailSession({"can't read the save state " + s_state_path});
			s_state_data = std::move(*data);
			s_state_size = static_cast<u32>(s_state_data.size());
			s_state_hash = XXH3_64bits(s_state_data.data(), s_state_data.size());
			s_state_phase = StatePhase::Transfer;
			Log("starting from save state %s (%u KB)", s_state_path.c_str(), s_state_size / 1024);
		}

		Log("waiting for the other player...");
		Clock::time_point last_hello = {};
		Clock::time_point last_join = {};
		Clock::time_point last_notice = Clock::now();
		for (;;)
		{
			const Clock::time_point now = Clock::now();
			if (s_use_lobby && !s_lobby_paired)
			{
				// Nowhere to send HELLOs yet; keep asking the lobby.
				if (now - last_join >= std::chrono::milliseconds(500))
				{
					SendLobbyJoin();
					last_join = now;
				}
			}
			else if (now - last_hello >= HELLO_INTERVAL)
			{
				UpdateRoute();
				SendHello();
				last_hello = now;
			}

			pollfd pfd = {s_socket, POLLIN, 0};
			poll(&pfd, 1, 10);
			Receive();

			if (s_is_host)
			{
				if (s_peer_checked && !s_host_ready && s_rtt_samples >= HANDSHAKE_RTT_SAMPLES)
				{
					s_start_delay = s_fixed_delay ? s_delay : DelayForRtt();
					s_host_ready = true;
					SendHello();
					last_hello = now;
				}
				// The guest starts as soon as it has our choice; its first input
				// packet also tells us, in case its ready HELLOs were lost.
				if (s_host_ready && (s_peer_ready || s_peer_sent_input))
					break;
			}
			else if (s_peer_checked && s_host_ready)
			{
				s_start_delay = s_host_delay;
				s_session_started = true; // makes our HELLOs say "ready"
				for (int i = 0; i < 3; i++)
					SendHello();
				break;
			}

			if (VMStopping())
				return false;
			if (now - last_notice > std::chrono::seconds(5))
			{
				last_notice = now;
				Log(s_peer_checked ? "measuring the connection..." :
					(s_use_lobby && !s_lobby_paired) ? "still waiting for the lobby to pair us..." :
													   "still waiting for the other player...");
			}
		}

		s_session_started = true;
		s_delay = s_start_delay;
		s_second_start = Clock::now();
		s_last_recorded = static_cast<s64>(s_start_delay) - 1;
		static constexpr const char* route_names[] = {"direct", "probing", "relayed"};
		Log("session started: delay %u frames (%.0f ms), rtt %.1f ms (min %.1f ms), %s", s_start_delay,
			s_start_delay * FrameMs(), s_srtt_ms, RoundTripMs(),
			s_use_lobby ? route_names[static_cast<int>(s_route.load())] : "direct");
		return true;
	}

	// ------------------------------------------------------------------------
	// Save-state transfer (runs at the vsync after the handshake)
	// ------------------------------------------------------------------------

	/// Host: sends every chunk until the guest has them all. Chunks the guest
	/// hasn't acknowledged are resent after about two round trips.
	static bool SendState()
	{
		std::vector<Clock::time_point> sent_at(s_state_chunks);
		const Clock::time_point start = Clock::now();
		Clock::time_point last_progress = start, last_log = start;
		u32 last_count = 0;
		u32 base = 0;
		while (!s_state_complete)
		{
			const Clock::time_point now = Clock::now();
			const auto resend_after = std::chrono::milliseconds(std::max(20, static_cast<int>(RoundTripMs() * 1.5 + 5)));
			while (base < s_state_chunks && s_state_have[base])
				base++;
			for (u32 i = base; i < std::min(base + STATE_WINDOW, s_state_chunks); i++)
			{
				if (s_state_have[i] || (sent_at[i] != Clock::time_point() && now - sent_at[i] < resend_after))
					continue;
				StateChunkPacket chunk = {};
				FillHeader(chunk.header, PACKET_STATE_CHUNK);
				chunk.index = i;
				const u64 offset = u64{i} * STATE_CHUNK_SIZE;
				chunk.size = static_cast<u16>(std::min<u64>(STATE_CHUNK_SIZE, s_state_size - offset));
				std::memcpy(chunk.data, s_state_data.data() + offset, chunk.size);
				SendPacket(&chunk, sizeof(chunk));
				sent_at[i] = now;
			}

			pollfd pfd = {s_socket, POLLIN, 0};
			poll(&pfd, 1, 1);
			Receive();

			if (s_state_have_count != last_count)
			{
				last_count = s_state_have_count;
				last_progress = now;
			}
			if (now - last_log > std::chrono::seconds(2))
			{
				last_log = now;
				Log("sending the save state: %u of %u KB", static_cast<u32>(u64{s_state_have_count} * STATE_CHUNK_SIZE / 1024),
					s_state_size / 1024);
			}
			if (now - last_progress > std::chrono::seconds(30) || VMStopping())
			{
				Log("error: the other player stopped receiving the save state");
				return false;
			}
		}
		const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
		Log("save state sent: %u KB in %.1f s", s_state_size / 1024, seconds);
		return true;
	}

	/// Guest: collects the chunks, acknowledging every 10 ms, checks the hash
	/// and writes the file.
	static bool ReceiveState()
	{
		const Clock::time_point start = Clock::now();
		Clock::time_point last_progress = start, last_log = start;
		u32 last_count = 0;
		while (s_state_have_count < s_state_chunks)
		{
			pollfd pfd = {s_socket, POLLIN, 0};
			poll(&pfd, 1, 1);
			Receive();

			const Clock::time_point now = Clock::now();
			if (now - s_state_last_ack > std::chrono::milliseconds(10))
				SendStateAck();
			if (s_state_have_count != last_count)
			{
				last_count = s_state_have_count;
				last_progress = now;
			}
			if (now - last_log > std::chrono::seconds(2))
			{
				last_log = now;
				Log("receiving the save state: %u of %u KB", static_cast<u32>(u64{s_state_have_count} * STATE_CHUNK_SIZE / 1024),
					s_state_size / 1024);
			}
			if (now - last_progress > std::chrono::seconds(30) || VMStopping())
			{
				Log("error: the host stopped sending the save state");
				return false;
			}
		}
		if (XXH3_64bits(s_state_data.data(), s_state_data.size()) != s_state_hash)
		{
			Log("error: the received save state is corrupt (hash mismatch)");
			return false;
		}
		if (!FileSystem::WriteBinaryFile(s_state_path.c_str(), s_state_data.data(), s_state_data.size()))
		{
			Log("error: can't write the received save state to %s", s_state_path.c_str());
			return false;
		}
		s_state_complete = true;
		for (int i = 0; i < 5; i++)
			SendStateAck(); // "done"; more follow if the host keeps sending
		const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
		Log("save state received: %u KB in %.1f s", s_state_size / 1024, seconds);
		return true;
	}

	/// Both machines: load the state later in this same vsync (queued work is
	/// run when the CPU thread pumps messages after the vsync hooks). The
	/// memory-card-busy check of VMManager::LoadState is skipped on purpose:
	/// it depends on real time, so it could refuse on one machine only.
	static void QueueStateLoad()
	{
		Host::RunOnCPUThread([path = s_state_path]() {
			Error error;
			if (SaveState_UnzipFromDisk(path, &error))
				Log("save state loaded; netplay frame 0 is the next frame");
			else
				Log("error: loading the save state failed: %s", error.GetDescription().c_str());
		});
	}

	static bool TransferState()
	{
		s_state_chunks = (s_state_size + STATE_CHUNK_SIZE - 1) / STATE_CHUNK_SIZE;
		s_state_have.assign(s_state_chunks, false);
		s_state_have_count = 0;
		if (!s_is_host)
		{
			s_state_data.assign(s_state_size, 0);
			s_state_path = Path::Combine(EmuFolders::DataRoot, "netplay-received.p2s");
		}
		Log("%s the save state (%u KB)...", s_is_host ? "sending" : "receiving", s_state_size / 1024);
		if (!(s_is_host ? SendState() : ReceiveState()))
			return false;
		s_state_data.clear();
		s_state_data.shrink_to_fit();
		QueueStateLoad();
		return true;
	}

	// ------------------------------------------------------------------------
	// Lockstep
	// ------------------------------------------------------------------------

	static bool HaveRemote(s64 frame)
	{
		return frame < static_cast<s64>(s_start_delay) || s_remote[frame % HISTORY].frame == frame;
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
		std::call_once(s_init_once, Initialize);
		if (!s_active)
			return;
		if (!s_session_started && !Handshake())
		{
			s_active = false;
			return;
		}
		UpdateRoute();

		if (s_state_phase == StatePhase::Transfer)
		{
			s_state_phase = StatePhase::Done;
			if (!TransferState())
			{
				Log("netplay stopped");
				s_active = false;
				return;
			}
			// The state loads later in this vsync; lockstep frame 0 is the next one.
			s_second_start = Clock::now();
			return;
		}

		const s64 f = s_frame;

		for (const auto& [frame, ms] : s_latency_plan)
		{
			if (frame == f)
			{
				Log("frame %lld: simulated latency %u -> %u ms", static_cast<long long>(f), s_latency_ms, ms);
				s_latency_ms = ms;
			}
		}

		// 1. Fingerprint the state this frame produced, for desync checks.
		if (f % HASH_INTERVAL == 0)
		{
			s_last_hash_frame = f;
			s_last_hash = HashState();
			s_own_hashes[(f / HASH_INTERVAL) % HASH_HISTORY] = {f, s_last_hash};
			CompareHashes(f);
		}

		// 2. Wait for the peer's input for this frame. The peer that runs
		// ahead waits here each frame; waiting before reading our own pad (step
		// 3) means that wait doesn't add to our input lag. It can't deadlock:
		// the peer recorded frame f by its frame f - 1, which only needed our
		// input up to f - 1, recorded at our frame f - 2 or earlier.
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
				UpdateRoute();
				SendInput(); // keep the peer fed in case our last packet was lost
				last_send = now;
			}
			if (!warned && now - start > std::chrono::seconds(3))
			{
				warned = true;
				Log("waiting for peer at frame %lld...", static_cast<long long>(f));
			}
			if (now - start > std::chrono::seconds(30) || VMStopping())
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

		// 3. Record our input for every frame up to f + delay not yet recorded,
		// and send it. After the delay drops, this records nothing until
		// f + delay passes the newest recorded frame.
		const s64 target = f + s_delay;
		for (s64 x = s_last_recorded + 1; x <= target; x++)
		{
			Input local;
			if (s_scripted)
				local = ScriptedInput(x);
			else
				for (u32 i = 0; i < NUM_INPUTS; i++)
					local[i] = s_live[i].load(std::memory_order_relaxed);
			s_local[x % HISTORY] = {x, local};
		}
		s_last_recorded = std::max(s_last_recorded, target);
		SendInput();

		// 4. Both machines apply the same inputs: host on port 1, guest on port 2.
		const Input& ours = InputFor(s_local, f);
		const Input& theirs = InputFor(s_remote, f);
		Apply(0, s_is_host ? ours : theirs);
		Apply(1, s_is_host ? theirs : ours);

		if (f > 0 && f % 60 == 0)
		{
			const Clock::time_point now = Clock::now();
			const double second_ms = std::chrono::duration<double, std::milli>(now - s_second_start).count();
			s_second_start = now;
			Log("frame %lld: delay %u, rtt %.1f ms, 60 frames took %.0f ms, wait avg %.2f ms max %.1f ms, "
				"%u/60 frames stalled >1ms, sent %u recv %u, hash checks ok %u, desyncs %u, state %016llx",
				static_cast<long long>(f), s_delay, s_srtt_ms, second_ms, s_wait_total_ms / 60.0, s_wait_max_ms,
				s_stalled_frames, s_sent, s_received, s_hash_ok, s_desyncs, static_cast<unsigned long long>(s_last_hash));
			AdaptDelay(second_ms);
			RotateRttWindow();
			s_wait_total_ms = s_wait_max_ms = 0;
			s_stalled_frames = s_sent = s_received = 0;
		}

		s_frame++;
		if (s_frames_to_run && static_cast<u64>(s_frame) >= s_frames_to_run)
		{
			// Let the peer reach the end too before we disappear.
			for (int i = 0; i < 20 + static_cast<int>(s_latency_ms / 10); i++)
			{
				SendInput();
				SleepMs(10);
			}
			Log("done: %lld frames, hash checks ok %u, desyncs %u, final delay %u", static_cast<long long>(s_frame),
				s_hash_ok, s_desyncs, s_delay);
			std::fclose(s_log);
			std::_Exit(0);
		}
	}
} // namespace Netplay
