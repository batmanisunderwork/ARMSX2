// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

/// Netplay feasibility test. Inactive unless ARMSX2_DETERMINISM_LOG is set.
///
/// When active, every vsync it feeds scripted (seeded, repeatable) input to
/// controller port 1 and writes a hash of the emulated machine's memory to the
/// log. Two runs with the same seed from the same start must produce identical
/// logs if emulation is deterministic, which lockstep netplay depends on.
///
/// Environment:
///   ARMSX2_DETERMINISM_LOG     output file (one line per frame)
///   ARMSX2_DETERMINISM_FRAMES  frames to run before exiting (default 3600)
///   ARMSX2_DETERMINISM_SEED    input script seed (default 1)
namespace DeterminismTest
{
	void OnVSync();
} // namespace DeterminismTest
