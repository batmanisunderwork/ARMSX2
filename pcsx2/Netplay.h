// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/Pcsx2Defs.h"

/// Prototype two-player delay-based lockstep netplay.
///
/// Both peers boot the same game with the same settings. Every vsync each peer
/// sends its local controller state for frame (f + delay), waits until it has
/// the other peer's state for frame f, then applies both: the host drives
/// port 1 and the guest port 2, on both machines, so both emulate identically.
/// Every 60 frames both hash the machine state and compare to detect desyncs.
///
/// Inactive unless ARMSX2_NETPLAY is set. Environment:
///   ARMSX2_NETPLAY        "host" or "join"
///   ARMSX2_NETPLAY_PORT   local UDP port (default 7777 host / 7778 join)
///   ARMSX2_NETPLAY_PEER   peer address "ip:port"
///   ARMSX2_NETPLAY_DELAY  input delay in frames (default 3)
///   ARMSX2_NETPLAY_LOG    log file (per-second stats, desync checks)
///   ARMSX2_NETPLAY_SCRIPT seed: play scripted input instead of the real pad
///   ARMSX2_NETPLAY_FRAMES exit after this many frames (for automated tests)
///   ARMSX2_NETPLAY_LOSS   simulated outgoing packet loss, percent
namespace Netplay
{
	/// Called at every vsync on the CPU thread. Blocks until the peer's input
	/// for this frame has arrived.
	void OnVSync();

	/// Called for every local controller input. Returns true if netplay took
	/// it (it will be applied in lockstep instead of immediately).
	bool CaptureLocalInput(u32 controller, u32 bind, float value);
} // namespace Netplay
