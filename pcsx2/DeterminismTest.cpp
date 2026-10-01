// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "DeterminismTest.h"

#include "Host.h"
#include "IopMem.h"
#include "Memory.h"
#include "SIO/Pad/Pad.h"
#include "SIO/Pad/PadDualshock2.h"
#include "VMManager.h"
#include "VUmicro.h"

#define XXH_STATIC_LINKING_ONLY 1
#define XXH_INLINE_ALL 1
#include "xxhash.h"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace DeterminismTest
{
	static bool s_initialized = false;
	static std::FILE* s_log = nullptr;
	static u64 s_frame = 0;
	static u64 s_frames_to_run = 3600;
	static u32 s_seed = 1;
	static u64 s_dump_frame = ~0ull;
	static const char* s_dump_path = nullptr;
	static u64 s_save_frame = ~0ull;
	static std::string s_save_path;

	/// Deterministic pseudo-random number for (seed, n).
	static u32 Mix(u32 n)
	{
		u32 x = n * 0x9E3779B1u ^ s_seed * 0x85EBCA77u;
		x ^= x >> 16;
		x *= 0x7FEB352Du;
		x ^= x >> 15;
		x *= 0x846CA68Bu;
		x ^= x >> 16;
		return x;
	}

	/// The input script: new buttons every 8 frames, a mix of menu presses
	/// (Start/Cross) and fighting inputs (d-pad, face buttons, left stick).
	static void ApplyScriptedInput(u64 frame)
	{
		using In = PadDualshock2::Inputs;
		static constexpr u32 buttons[] = {
			In::PAD_UP, In::PAD_RIGHT, In::PAD_DOWN, In::PAD_LEFT,
			In::PAD_TRIANGLE, In::PAD_CIRCLE, In::PAD_CROSS, In::PAD_SQUARE,
			In::PAD_START, In::PAD_L1, In::PAD_R1,
		};

		const u32 r = Mix(static_cast<u32>(frame / 8));
		for (u32 i = 0; i < std::size(buttons); i++)
		{
			// Start rarely (it pauses fights), Cross often (it confirms menus).
			const u32 odds = buttons[i] == In::PAD_START ? 24 : buttons[i] == In::PAD_CROSS ? 3 : 6;
			const bool down = (Mix(static_cast<u32>(frame / 8) * 31 + i) % odds) == 0;
			Pad::SetControllerState(0, buttons[i], down ? 1.0f : 0.0f);
		}
		const float lx = static_cast<float>(static_cast<int>(r & 0xFF) - 128) / 128.0f;
		Pad::SetControllerState(0, In::PAD_L_RIGHT, lx > 0 ? lx : 0.0f);
		Pad::SetControllerState(0, In::PAD_L_LEFT, lx < 0 ? -lx : 0.0f);
	}

	void OnVSync()
	{
		if (!s_initialized)
		{
			s_initialized = true;
			const char* path = std::getenv("ARMSX2_DETERMINISM_LOG");
			if (!path || !*path)
				return;
			s_log = std::fopen(path, "w");
			if (const char* frames = std::getenv("ARMSX2_DETERMINISM_FRAMES"))
				s_frames_to_run = std::strtoull(frames, nullptr, 10);
			if (const char* seed = std::getenv("ARMSX2_DETERMINISM_SEED"))
				s_seed = static_cast<u32>(std::strtoul(seed, nullptr, 10));
			// Optional raw dump of EE main RAM at one frame, to locate differences.
			if (const char* dump = std::getenv("ARMSX2_DETERMINISM_DUMP_FRAME"))
				s_dump_frame = std::strtoull(dump, nullptr, 10);
			s_dump_path = std::getenv("ARMSX2_DETERMINISM_DUMP_PATH");
			// Optional save state at one frame (queued work runs later in this
			// same vsync), and the frame number to count from for a run that
			// was started from such a state (-statefile): the save frame + 1.
			if (const char* v = std::getenv("ARMSX2_DETERMINISM_SAVE_FRAME"))
				s_save_frame = std::strtoull(v, nullptr, 10);
			if (const char* v = std::getenv("ARMSX2_DETERMINISM_SAVE_PATH"))
				s_save_path = v;
			if (const char* v = std::getenv("ARMSX2_DETERMINISM_FIRST_FRAME"))
				s_frame = std::strtoull(v, nullptr, 10);
			s_frames_to_run += s_frame;
			if (s_log)
				std::fprintf(s_log, "# frame ee iop vu0 vu1 seed=%u\n", s_seed);
		}
		if (!s_log)
			return;

		// Hash the state produced by the frame that just finished.
		const u64 ee = XXH3_64bits(eeMem->Main, Ps2MemSize::MainRam);
		const u64 iop = XXH3_64bits(iopMem->Main, Ps2MemSize::IopRam);
		const u64 vu0 = XXH3_64bits(vuRegs[0].Mem, VU0_MEMSIZE);
		const u64 vu1 = XXH3_64bits(vuRegs[1].Mem, VU1_MEMSIZE);
		std::fprintf(s_log, "%llu %016llx %016llx %016llx %016llx\n", static_cast<unsigned long long>(s_frame),
			static_cast<unsigned long long>(ee), static_cast<unsigned long long>(iop),
			static_cast<unsigned long long>(vu0), static_cast<unsigned long long>(vu1));

		if (s_frame == s_dump_frame && s_dump_path)
		{
			if (std::FILE* dump = std::fopen(s_dump_path, "wb"))
			{
				std::fwrite(eeMem->Main, 1, Ps2MemSize::MainRam, dump);
				std::fclose(dump);
			}
		}

		// Input for the next frame is set at the same emulated moment every run.
		ApplyScriptedInput(s_frame);

		if (s_frame == s_save_frame && !s_save_path.empty())
		{
			Host::RunOnCPUThread([path = s_save_path]() {
				VMManager::SaveState(path.c_str(), false, false, [](const std::string& error) {
					if (s_log)
						std::fprintf(s_log, "# save state failed: %s\n", error.c_str());
				});
			});
		}

		if (++s_frame >= s_frames_to_run)
		{
			std::fclose(s_log);
			s_log = nullptr;
			std::fflush(nullptr); // other debug outputs (e.g. ARMSX2_IOP_TRACE)
			std::_Exit(0);
		}
	}
} // namespace DeterminismTest
