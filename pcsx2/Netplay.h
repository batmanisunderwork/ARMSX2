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
/// Before frame 0 the peers shake hands: each checks that the other runs the
/// same build and architecture, game, BIOS, memory cards and emulation
/// settings (and exits with a list of the differences otherwise), then the
/// host measures the round-trip time and picks the starting delay. During play
/// the host keeps adapting the delay to the round-trip time and to stalls, and
/// the guest follows it.
///
/// Inactive unless ARMSX2_NETPLAY is set. Environment:
///   ARMSX2_NETPLAY           "host" or "join"
///   ARMSX2_NETPLAY_PORT      local UDP port (default 7777 host / 7778 join)
///   ARMSX2_NETPLAY_PEER      peer address "ip:port", or instead:
///   ARMSX2_NETPLAY_SERVER    lobby "host:port" and
///   ARMSX2_NETPLAY_ROOM      room code (same for both players); the lobby
///                            pairs the players, who then connect directly
///                            (UDP hole punching) or through the lobby's relay
///   ARMSX2_NETPLAY_FORCE_RELAY  skip the direct attempt (testing)
///   ARMSX2_NETPLAY_DELAY     host: fixed input delay in frames; unset or
///                            "auto" adapts it to the connection
///   ARMSX2_NETPLAY_MIN_DELAY host: adaptive delay range (default 2..15)
///   ARMSX2_NETPLAY_MAX_DELAY
///   ARMSX2_NETPLAY_LOG       log file (per-second stats, desync checks)
///   ARMSX2_NETPLAY_SCRIPT    seed: play scripted input instead of the real pad
///   ARMSX2_NETPLAY_FRAMES    exit after this many frames (for automated tests)
///   ARMSX2_NETPLAY_LOSS      simulated outgoing packet loss, percent
///   ARMSX2_NETPLAY_LATENCY   simulated one-way latency, ms
///   ARMSX2_NETPLAY_LATENCY_PLAN  "frame:ms,..." changes it during the run
namespace Netplay
{
	/// Called at every vsync on the CPU thread. Blocks until the peer's input
	/// for this frame has arrived.
	void OnVSync();

	/// Called for every local controller input. Returns true if netplay took
	/// it (it will be applied in lockstep instead of immediately).
	bool CaptureLocalInput(u32 controller, u32 bind, float value);
} // namespace Netplay
