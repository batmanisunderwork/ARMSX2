// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "Input/InputSource.h"

#include <array>
#include <chrono>
#include <string>
#include <unordered_map>

#include <sys/socket.h>

#ifdef __APPLE__
#include <dns_sd.h>
#endif

/// Phones running the Virtual Gamepad app (iOS/Android) as controllers over Wi-Fi.
///
/// Each phone streams its full controller state as small JSON UDP packets to
/// port 8888 and gets back {"player":N}. Phones are told apart by the "id" in
/// their packets, so a phone that reconnects keeps its slot. The service is
/// advertised over Bonjour as _vgamepad._udp so the apps find it on their own.
class PhoneInputSource final : public InputSource
{
public:
	enum : u32
	{
		NUM_CONTROLLERS = 4,
		DEFAULT_PORT = 8888,
	};

	enum : u32
	{
		BUTTON_CROSS,
		BUTTON_CIRCLE,
		BUTTON_SQUARE,
		BUTTON_TRIANGLE,
		BUTTON_L1,
		BUTTON_R1,
		BUTTON_L2,
		BUTTON_R2,
		BUTTON_L3,
		BUTTON_R3,
		BUTTON_START,
		BUTTON_SELECT,
		BUTTON_DPAD_UP,
		BUTTON_DPAD_DOWN,
		BUTTON_DPAD_LEFT,
		BUTTON_DPAD_RIGHT,
		NUM_BUTTONS,
	};

	enum : u32
	{
		AXIS_LEFTX,
		AXIS_LEFTY,
		AXIS_RIGHTX,
		AXIS_RIGHTY,
		NUM_AXES,
	};

	PhoneInputSource();
	~PhoneInputSource() override;

	bool Initialize(SettingsInterface& si, std::unique_lock<std::mutex>& settings_lock) override;
	void UpdateSettings(SettingsInterface& si, std::unique_lock<std::mutex>& settings_lock) override;
	bool ReloadDevices() override;
	void Shutdown() override;
	bool IsInitialized() override;

	void PollEvents() override;
	std::vector<std::pair<std::string, std::string>> EnumerateDevices() override;
	std::vector<InputBindingKey> EnumerateMotors() override;
	bool GetGenericBindingMapping(const std::string_view device, InputManager::GenericInputBindingMapping* mapping) override;
	InputLayout GetControllerLayout(u32 index) override;
	void UpdateMotorState(InputBindingKey key, float intensity) override;

	std::optional<InputBindingKey> ParseKeyString(const std::string_view device, const std::string_view binding) override;
	TinyString ConvertKeyToString(InputBindingKey key, bool display = false, bool migration = false) override;
	TinyString ConvertKeyToIcon(InputBindingKey key) override;

private:
	using Clock = std::chrono::steady_clock;

	struct PadState
	{
		std::array<bool, NUM_BUTTONS> buttons = {};
		std::array<float, NUM_AXES> axes = {};
	};

	struct Slot
	{
		/// The phone's id, or empty if the slot has never been used.
		std::string owner;
		/// Receiving packets right now; goes false after STALE_TIMEOUT.
		bool active = false;
		Clock::time_point last_seen = {};
		Clock::time_point last_reply = {};
		s64 last_seq = -1;
		PadState state;
	};

	bool OpenSocket(u16 port);
	void CloseSocket();
	void HandlePacket(std::string_view packet, const sockaddr_storage& from, socklen_t from_len, Clock::time_point now);
	int SlotFor(const std::string& owner, Clock::time_point now);
	void ApplyState(u32 index, const PadState& new_state);
	void Reply(int player, const sockaddr_storage& to, socklen_t to_len);
	void RegisterBonjour(u16 port);
	void UnregisterBonjour();

	int m_socket = -1;
	u16 m_port = DEFAULT_PORT;
	std::array<Slot, NUM_CONTROLLERS> m_slots;
	/// Last "full" reply per turned-away phone, to throttle them.
	std::unordered_map<std::string, Clock::time_point> m_turned_away;

#ifdef __APPLE__
	DNSServiceRef m_bonjour = nullptr;
#endif
};
