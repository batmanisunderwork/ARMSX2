// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "Netplay.h"

#include "BuildVersion.h"
#include "Config.h"
#include "IopMem.h"
#include "Memory.h"
#include "SIO/Pad/Pad.h"
#include "SIO/Pad/PadDualshock2.h"
#include "VMManager.h"
#include "VUmicro.h"

#include "common/Console.h"
#include "common/FileSystem.h"

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
	static constexpr u8 PROTOCOL_VERSION = 2;
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
	};

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
		u8 reserved;
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
#pragma pack(pop)

	static constexpr size_t MAX_PACKET_SIZE = std::max(sizeof(HelloPacket), sizeof(InputPacket));
	using PacketBuffer = std::array<u8, MAX_PACKET_SIZE>;

	static std::once_flag s_init_once;
	static bool s_active = false;
	static bool s_is_host = true;
	static bool s_session_started = false;
	static socket_t s_socket = BAD_SOCKET;
	static sockaddr_in s_peer = {};
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
		if (!s_is_host)
			Log("netplay guest (player 2), port %u, peer %s%s; the host chooses the input delay", port, peer,
				s_scripted ? ", scripted input" : "");
		else if (s_fixed_delay)
			Log("netplay host (player 1), port %u, peer %s, fixed delay %u frames%s", port, peer, s_delay,
				s_scripted ? ", scripted input" : "");
		else
			Log("netplay host (player 1), port %u, peer %s, adaptive delay %u-%u frames%s", port, peer, s_min_delay,
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

	/// Delay that covers the one-way latency plus a little slack for frame
	/// pacing. Matches the Mac measurements: 40 ms one way -> 3 frames,
	/// 80 ms -> 6. Jitter is handled by AdaptDelay() watching for stalls.
	static u32 DelayForRtt()
	{
		const double needed_ms = RoundTripMs() / 2 + 4.0;
		const u32 frames = static_cast<u32>(std::ceil(needed_ms / FRAME_MS));
		return std::clamp(frames, s_min_delay, s_max_delay);
	}

	static void SetDelay(u32 delay, const char* reason)
	{
		if (delay == s_delay)
			return;
		Log("frame %lld: delay %u -> %u (%s; rtt %.1f ms, min %.1f ms)", static_cast<long long>(s_frame), s_delay,
			delay, reason, s_srtt_ms, RoundTripMs());
		s_delay = delay;
	}

	/// Host, once per second: follow the round-trip time. Raise at once, lower
	/// one frame at a time after 3 calm seconds, so a brief spike doesn't make
	/// the delay jump around.
	static void AdaptDelay()
	{
		if (!s_is_host || s_fixed_delay || s_rtt_samples == 0)
			return;

		const u32 by_rtt = DelayForRtt();
		u32 target = by_rtt;

		// Frames stall although the delay covers the round trip: jitter or
		// uneven frame pacing. Allow up to 2 frames extra, and keep that for
		// 10 seconds before trusting the round-trip time again.
		if (s_stalled_frames > 6 && s_delay >= by_rtt && s_delay < std::min(by_rtt + 2, s_max_delay))
		{
			s_stall_floor = s_delay + 1;
			s_stall_floor_until = s_frame + 600;
		}
		if (s_frame < s_stall_floor_until)
			target = std::max(target, s_stall_floor);

		if (target > s_delay)
		{
			s_lower_streak = 0;
			SetDelay(target, target > by_rtt ? "frames stalling" : "latency rose");
		}
		else if (target < s_delay)
		{
			if (++s_lower_streak >= 3)
			{
				s_lower_streak = 0;
				SetDelay(s_delay - 1, "latency fell");
			}
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

	static void Receive()
	{
		PacketBuffer buffer;
		for (;;)
		{
			const int len = static_cast<int>(recv(s_socket, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0));
			if (len < 0)
				break;
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

		Log("waiting for the other player...");
		Clock::time_point last_hello = {};
		Clock::time_point last_notice = Clock::now();
		for (;;)
		{
			const Clock::time_point now = Clock::now();
			if (now - last_hello >= HELLO_INTERVAL)
			{
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
				Log(s_peer_checked ? "measuring the connection..." : "still waiting for the other player...");
			}
		}

		s_session_started = true;
		s_delay = s_start_delay;
		s_last_recorded = static_cast<s64>(s_start_delay) - 1;
		Log("session started: delay %u frames (%.0f ms), rtt %.1f ms (min %.1f ms)", s_start_delay,
			s_start_delay * FRAME_MS, s_srtt_ms, RoundTripMs());
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

		const s64 f = s_frame;

		for (const auto& [frame, ms] : s_latency_plan)
		{
			if (frame == f)
			{
				Log("frame %lld: simulated latency %u -> %u ms", static_cast<long long>(f), s_latency_ms, ms);
				s_latency_ms = ms;
			}
		}

		// 1. Record our input for every frame up to f + delay not yet recorded.
		// After the delay drops, this records nothing until f + delay passes
		// the newest recorded frame.
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

		// 2. Fingerprint the state this frame produced, for desync checks.
		if (f % HASH_INTERVAL == 0)
		{
			s_last_hash_frame = f;
			s_last_hash = HashState();
			s_own_hashes[(f / HASH_INTERVAL) % HASH_HISTORY] = {f, s_last_hash};
			CompareHashes(f);
		}

		// 3. Send, then wait for the peer's input for this frame.
		SendInput();
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

		// 4. Both machines apply the same inputs: host on port 1, guest on port 2.
		const Input& ours = InputFor(s_local, f);
		const Input& theirs = InputFor(s_remote, f);
		Apply(0, s_is_host ? ours : theirs);
		Apply(1, s_is_host ? theirs : ours);

		if (f > 0 && f % 60 == 0)
		{
			Log("frame %lld: delay %u, rtt %.1f ms, wait avg %.2f ms max %.1f ms, %u/60 frames stalled >1ms, "
				"sent %u recv %u, hash checks ok %u, desyncs %u, state %016llx",
				static_cast<long long>(f), s_delay, s_srtt_ms, s_wait_total_ms / 60.0, s_wait_max_ms, s_stalled_frames,
				s_sent, s_received, s_hash_ok, s_desyncs, static_cast<unsigned long long>(s_last_hash));
			AdaptDelay();
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
