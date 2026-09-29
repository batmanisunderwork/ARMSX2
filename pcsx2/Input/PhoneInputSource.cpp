// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "Input/PhoneInputSource.h"
#include "Input/InputManager.h"

#include "common/Console.h"
#include "common/SettingsInterface.h"
#include "common/StringUtil.h"

#include "IconsPromptFont.h"

#include "fmt/format.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>

// Release a phone's input if it goes quiet this long (phone locked, Wi-Fi
// dropped). The apps resend their state every 16 ms, but phone Wi-Fi often
// delivers packets in bursts with gaps of a few hundred ms, so this can't be
// much shorter without dropping held buttons. The apps release everything
// themselves when backgrounded.
static constexpr auto STALE_TIMEOUT = std::chrono::milliseconds(1000);
static constexpr auto REPLY_INTERVAL = std::chrono::milliseconds(500);
// A seq this far behind the last one is an app restart, not a late packet.
static constexpr s64 SEQ_RESET_WINDOW = 1000;

static constexpr const char* BONJOUR_TYPE = "_vgamepad._udp";

// Wire names used by the apps, in button enum order.
static constexpr const char* s_button_wire_names[PhoneInputSource::NUM_BUTTONS] = {
	"a", "b", "x", "y", "lb", "rb", "lt", "rt", "l3", "r3", "start", "select", "up", "down", "left", "right",
};
static constexpr const char* s_axis_wire_names[PhoneInputSource::NUM_AXES] = {"lx", "ly", "rx", "ry"};

static constexpr const char* s_button_setting_names[PhoneInputSource::NUM_BUTTONS] = {
	"Cross", "Circle", "Square", "Triangle", "L1", "R1", "L2", "R2", "L3", "R3", "Start", "Select",
	"DPadUp", "DPadDown", "DPadLeft", "DPadRight",
};
static constexpr const char* s_button_display_names[PhoneInputSource::NUM_BUTTONS] = {
	"Cross", "Circle", "Square", "Triangle", "L1", "R1", "L2", "R2", "L3", "R3", "Start", "Select",
	"D-Pad Up", "D-Pad Down", "D-Pad Left", "D-Pad Right",
};
static constexpr const char* s_button_icons[PhoneInputSource::NUM_BUTTONS] = {
	ICON_PF_BUTTON_CROSS, ICON_PF_BUTTON_CIRCLE, ICON_PF_BUTTON_SQUARE, ICON_PF_BUTTON_TRIANGLE,
	ICON_PF_LEFT_SHOULDER_L1, ICON_PF_RIGHT_SHOULDER_R1, ICON_PF_LEFT_TRIGGER_L2, ICON_PF_RIGHT_TRIGGER_R2,
	ICON_PF_LEFT_ANALOG_CLICK, ICON_PF_RIGHT_ANALOG_CLICK, ICON_PF_START, ICON_PF_SELECT_SHARE,
	ICON_PF_DPAD_UP, ICON_PF_DPAD_DOWN, ICON_PF_DPAD_LEFT, ICON_PF_DPAD_RIGHT,
};
static const GenericInputBinding s_generic_button_mapping[PhoneInputSource::NUM_BUTTONS] = {
	GenericInputBinding::Cross, GenericInputBinding::Circle, GenericInputBinding::Square, GenericInputBinding::Triangle,
	GenericInputBinding::L1, GenericInputBinding::R1, GenericInputBinding::L2, GenericInputBinding::R2,
	GenericInputBinding::L3, GenericInputBinding::R3, GenericInputBinding::Start, GenericInputBinding::Select,
	GenericInputBinding::DPadUp, GenericInputBinding::DPadDown, GenericInputBinding::DPadLeft, GenericInputBinding::DPadRight,
};

static constexpr const char* s_axis_setting_names[PhoneInputSource::NUM_AXES] = {"LeftX", "LeftY", "RightX", "RightY"};
static constexpr const char* s_axis_display_names[PhoneInputSource::NUM_AXES] = {"Left X", "Left Y", "Right X", "Right Y"};
static constexpr const char* s_axis_icons[PhoneInputSource::NUM_AXES][2] = {
	{ICON_PF_LEFT_ANALOG_LEFT, ICON_PF_LEFT_ANALOG_RIGHT},
	{ICON_PF_LEFT_ANALOG_UP, ICON_PF_LEFT_ANALOG_DOWN},
	{ICON_PF_RIGHT_ANALOG_LEFT, ICON_PF_RIGHT_ANALOG_RIGHT},
	{ICON_PF_RIGHT_ANALOG_UP, ICON_PF_RIGHT_ANALOG_DOWN},
};
static const GenericInputBinding s_generic_axis_mapping[PhoneInputSource::NUM_AXES][2] = {
	{GenericInputBinding::LeftStickLeft, GenericInputBinding::LeftStickRight},
	{GenericInputBinding::LeftStickUp, GenericInputBinding::LeftStickDown},
	{GenericInputBinding::RightStickLeft, GenericInputBinding::RightStickRight},
	{GenericInputBinding::RightStickUp, GenericInputBinding::RightStickDown},
};

// ------------------------------------------------------------------------
// Packet parsing. The apps send flat, known JSON where every key is unique,
// e.g. {"seq":1,"id":"...","buttons":{"a":1,...},"dpad":{...},"axes":{"lx":0.5,...}},
// so a key search is enough and avoids pulling in a JSON library.
// ------------------------------------------------------------------------

/// Position just after `"key":`, or npos.
static size_t FindValue(std::string_view json, std::string_view key)
{
	const std::string needle = fmt::format("\"{}\"", key);
	size_t pos = 0;
	while ((pos = json.find(needle, pos)) != std::string_view::npos)
	{
		size_t p = pos + needle.size();
		while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p])))
			p++;
		if (p < json.size() && json[p] == ':')
		{
			p++;
			while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p])))
				p++;
			return p;
		}
		pos = p;
	}
	return std::string_view::npos;
}

static std::optional<double> FindNumber(std::string_view json, std::string_view key)
{
	const size_t start = FindValue(json, key);
	if (start == std::string_view::npos)
		return std::nullopt;
	size_t end = start;
	while (end < json.size() && std::strchr("+-0123456789.eE", json[end]) && json[end] != '\0')
		end++;
	return StringUtil::FromChars<double>(json.substr(start, end - start));
}

static std::optional<std::string> FindString(std::string_view json, std::string_view key)
{
	const size_t start = FindValue(json, key);
	if (start == std::string_view::npos || json[start] != '"')
		return std::nullopt;
	const size_t end = json.find('"', start + 1);
	if (end == std::string_view::npos)
		return std::nullopt;
	return std::string(json.substr(start + 1, end - start - 1));
}

// ------------------------------------------------------------------------

PhoneInputSource::PhoneInputSource() = default;

PhoneInputSource::~PhoneInputSource()
{
	Shutdown();
}

bool PhoneInputSource::Initialize(SettingsInterface& si, std::unique_lock<std::mutex>& settings_lock)
{
	m_port = static_cast<u16>(si.GetUIntValue("InputSources", "PhonePort", DEFAULT_PORT));
	return OpenSocket(m_port);
}

void PhoneInputSource::UpdateSettings(SettingsInterface& si, std::unique_lock<std::mutex>& settings_lock)
{
	const u16 port = static_cast<u16>(si.GetUIntValue("InputSources", "PhonePort", DEFAULT_PORT));
	if (port != m_port || m_socket < 0)
	{
		Shutdown();
		m_port = port;
		OpenSocket(m_port);
	}
}

bool PhoneInputSource::ReloadDevices()
{
	return false;
}

void PhoneInputSource::Shutdown()
{
	for (u32 i = 0; i < NUM_CONTROLLERS; i++)
	{
		if (m_slots[i].active)
		{
			ApplyState(i, PadState());
			InputManager::OnInputDeviceDisconnected(
				{{.source_type = InputSourceType::Phone, .source_index = i}}, fmt::format("Phone-{}", i));
		}
		m_slots[i] = Slot();
	}
	m_turned_away.clear();
	CloseSocket();
}

bool PhoneInputSource::IsInitialized()
{
	return m_socket >= 0;
}

bool PhoneInputSource::OpenSocket(u16 port)
{
	// Dual-stack, so phones that resolve the Mac to an IPv6 address work too.
	const int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
	{
		ERROR_LOG("Phone controllers: socket() failed: {}", std::strerror(errno));
		return false;
	}

	const int off = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	sockaddr_in6 addr = {};
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(port);
	if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
	{
		ERROR_LOG("Phone controllers: can't listen on UDP port {} ({}). Is mac_server.py still running?", port,
			std::strerror(errno));
		close(fd);
		return false;
	}

	m_socket = fd;
	RegisterBonjour(port);
	INFO_LOG("Phone controllers: listening on UDP port {}", port);
	return true;
}

void PhoneInputSource::CloseSocket()
{
	UnregisterBonjour();
	if (m_socket >= 0)
	{
		close(m_socket);
		m_socket = -1;
	}
}

void PhoneInputSource::RegisterBonjour(u16 port)
{
#ifdef __APPLE__
	// A null name uses the Mac's name, e.g. "Rohans-MacBook-Air". No callback:
	// the registration stays up without us servicing the connection.
	const DNSServiceErrorType err = DNSServiceRegister(&m_bonjour, 0, kDNSServiceInterfaceIndexAny, nullptr,
		BONJOUR_TYPE, nullptr, nullptr, htons(port), 0, nullptr, nullptr, nullptr);
	if (err != kDNSServiceErr_NoError)
	{
		WARNING_LOG("Phone controllers: Bonjour registration failed ({}), phones must connect by IP", err);
		m_bonjour = nullptr;
	}
#endif
}

void PhoneInputSource::UnregisterBonjour()
{
#ifdef __APPLE__
	if (m_bonjour)
	{
		DNSServiceRefDeallocate(m_bonjour);
		m_bonjour = nullptr;
	}
#endif
}

void PhoneInputSource::PollEvents()
{
	if (m_socket < 0)
		return;

	const Clock::time_point now = Clock::now();

	char buffer[2048];
	for (;;)
	{
		sockaddr_storage from = {};
		socklen_t from_len = sizeof(from);
		const ssize_t len = recvfrom(m_socket, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
		if (len <= 0)
			break;
		HandlePacket(std::string_view(buffer, static_cast<size_t>(len)), from, from_len, now);
	}

	for (u32 i = 0; i < NUM_CONTROLLERS; i++)
	{
		Slot& slot = m_slots[i];
		if (slot.active && now - slot.last_seen > STALE_TIMEOUT)
		{
			slot.active = false;
			ApplyState(i, PadState());
			INFO_LOG("Phone controllers: player {} went quiet", i + 1);
			InputManager::OnInputDeviceDisconnected(
				{{.source_type = InputSourceType::Phone, .source_index = i}}, fmt::format("Phone-{}", i));
		}
	}
}

void PhoneInputSource::HandlePacket(
	std::string_view packet, const sockaddr_storage& from, socklen_t from_len, Clock::time_point now)
{
	// Older app builds without an id fall back to the sender's address.
	std::string owner;
	if (std::optional<std::string> id = FindString(packet, "id"); id.has_value() && !id->empty())
	{
		owner = std::move(*id);
	}
	else
	{
		char host[INET6_ADDRSTRLEN] = {};
		if (from.ss_family == AF_INET6)
			inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6&>(from).sin6_addr, host, sizeof(host));
		else
			inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in&>(from).sin_addr, host, sizeof(host));
		owner = host;
	}

	const int index = SlotFor(owner, now);
	if (index < 0)
	{
		auto it = m_turned_away.find(owner);
		if (it == m_turned_away.end())
		{
			WARNING_LOG("Phone controllers: all {} player slots taken, ignoring another phone", static_cast<u32>(NUM_CONTROLLERS));
			it = m_turned_away.emplace(owner, Clock::time_point()).first;
		}
		if (now - it->second >= REPLY_INTERVAL)
		{
			it->second = now;
			Reply(0, from, from_len);
		}
		return;
	}

	Slot& slot = m_slots[index];
	const bool was_active = slot.active;
	if (!was_active)
		slot.last_seq = -1; // the app may have restarted and reset its seq

	// Drop duplicates and packets that arrive out of order.
	if (const std::optional<double> seq = FindNumber(packet, "seq"); seq.has_value())
	{
		const s64 s = static_cast<s64>(*seq);
		if (slot.last_seq >= 0 && s <= slot.last_seq && slot.last_seq - s < SEQ_RESET_WINDOW)
			return;
		slot.last_seq = s;
	}

	slot.last_seen = now;
	if (!was_active)
	{
		slot.active = true;
		INFO_LOG("Phone controllers: player {} connected", index + 1);
		InputManager::OnInputDeviceConnected(fmt::format("Phone-{}", index), fmt::format("Phone Controller {}", index + 1));
	}

	PadState state;
	for (u32 i = 0; i < NUM_BUTTONS; i++)
		state.buttons[i] = FindNumber(packet, s_button_wire_names[i]).value_or(0.0) >= 0.5;
	for (u32 i = 0; i < NUM_AXES; i++)
	{
		const float value = std::clamp(static_cast<float>(FindNumber(packet, s_axis_wire_names[i]).value_or(0.0)), -1.0f, 1.0f);
		// The apps send y positive up; PCSX2 axes are positive down.
		state.axes[i] = (i == AXIS_LEFTY || i == AXIS_RIGHTY) ? -value : value;
	}
	ApplyState(static_cast<u32>(index), state);

	if (!was_active || now - slot.last_reply >= REPLY_INTERVAL)
	{
		slot.last_reply = now;
		Reply(index + 1, from, from_len);
	}
}

int PhoneInputSource::SlotFor(const std::string& owner, Clock::time_point now)
{
	// A phone gets its old player number back if nobody has taken it...
	for (u32 i = 0; i < NUM_CONTROLLERS; i++)
	{
		if (m_slots[i].owner == owner)
			return static_cast<int>(i);
	}
	// ...otherwise the lowest number whose phone isn't connected, like a
	// console. A lone phone is always Player 1.
	for (u32 i = 0; i < NUM_CONTROLLERS; i++)
	{
		Slot& slot = m_slots[i];
		if (slot.owner.empty() || !slot.active)
		{
			slot = Slot();
			slot.owner = owner;
			m_turned_away.erase(owner);
			return static_cast<int>(i);
		}
	}
	return -1;
}

void PhoneInputSource::ApplyState(u32 index, const PadState& new_state)
{
	PadState& old_state = m_slots[index].state;

	for (u32 i = 0; i < NUM_AXES; i++)
	{
		if (old_state.axes[i] != new_state.axes[i])
		{
			InputManager::InvokeEvents(MakeGenericControllerAxisKey(InputSourceType::Phone, index, i), new_state.axes[i],
				GenericInputBinding::Unknown, s_generic_axis_mapping[i][0], s_generic_axis_mapping[i][1]);
		}
	}
	for (u32 i = 0; i < NUM_BUTTONS; i++)
	{
		if (old_state.buttons[i] != new_state.buttons[i])
		{
			InputManager::InvokeEvents(MakeGenericControllerButtonKey(InputSourceType::Phone, index, i),
				new_state.buttons[i] ? 1.0f : 0.0f, s_generic_button_mapping[i]);
		}
	}

	old_state = new_state;
}

void PhoneInputSource::Reply(int player, const sockaddr_storage& to, socklen_t to_len)
{
	const std::string message =
		player > 0 ? fmt::format("{{\"player\":{}}}", player) : std::string("{\"player\":0,\"error\":\"full\"}");
	sendto(m_socket, message.data(), message.size(), 0, reinterpret_cast<const sockaddr*>(&to), to_len);
}

std::vector<std::pair<std::string, std::string>> PhoneInputSource::EnumerateDevices()
{
	// All four are always listed, so players can be mapped before their
	// phones connect.
	std::vector<std::pair<std::string, std::string>> ret;
	for (u32 i = 0; i < NUM_CONTROLLERS; i++)
		ret.emplace_back(fmt::format("Phone-{}", i), fmt::format("Phone Controller {}", i + 1));
	return ret;
}

std::vector<InputBindingKey> PhoneInputSource::EnumerateMotors()
{
	return {};
}

bool PhoneInputSource::GetGenericBindingMapping(const std::string_view device, InputManager::GenericInputBindingMapping* mapping)
{
	if (!device.starts_with("Phone-"))
		return false;

	const std::optional<s32> index = StringUtil::FromChars<s32>(device.substr(6));
	if (!index.has_value() || index.value() < 0 || index.value() >= static_cast<s32>(NUM_CONTROLLERS))
		return false;

	for (u32 i = 0; i < NUM_AXES; i++)
	{
		mapping->emplace_back(s_generic_axis_mapping[i][0], fmt::format("Phone-{}/-{}", *index, s_axis_setting_names[i]));
		mapping->emplace_back(s_generic_axis_mapping[i][1], fmt::format("Phone-{}/+{}", *index, s_axis_setting_names[i]));
	}
	for (u32 i = 0; i < NUM_BUTTONS; i++)
		mapping->emplace_back(s_generic_button_mapping[i], fmt::format("Phone-{}/{}", *index, s_button_setting_names[i]));

	return true;
}

InputLayout PhoneInputSource::GetControllerLayout(u32 index)
{
	return InputLayout::Playstation;
}

void PhoneInputSource::UpdateMotorState(InputBindingKey key, float intensity)
{
}

std::optional<InputBindingKey> PhoneInputSource::ParseKeyString(const std::string_view device, const std::string_view binding)
{
	if (!device.starts_with("Phone-") || binding.empty())
		return std::nullopt;

	const std::optional<s32> index = StringUtil::FromChars<s32>(device.substr(6));
	if (!index.has_value() || index.value() < 0 || index.value() >= static_cast<s32>(NUM_CONTROLLERS))
		return std::nullopt;

	InputBindingKey key = {};
	key.source_type = InputSourceType::Phone;
	key.source_index = static_cast<u32>(index.value());

	if (binding[0] == '+' || binding[0] == '-')
	{
		const std::string_view axis_name = binding.substr(1);
		for (u32 i = 0; i < NUM_AXES; i++)
		{
			if (axis_name == s_axis_setting_names[i])
			{
				key.source_subtype = InputSubclass::ControllerAxis;
				key.data = i;
				key.modifier = binding[0] == '-' ? InputModifier::Negate : InputModifier::None;
				return key;
			}
		}
	}
	else
	{
		for (u32 i = 0; i < NUM_BUTTONS; i++)
		{
			if (binding == s_button_setting_names[i])
			{
				key.source_subtype = InputSubclass::ControllerButton;
				key.data = i;
				return key;
			}
		}
	}

	return std::nullopt;
}

TinyString PhoneInputSource::ConvertKeyToString(InputBindingKey key, bool display, bool migration)
{
	TinyString ret;
	if (key.source_type != InputSourceType::Phone)
		return ret;

	if (key.source_subtype == InputSubclass::ControllerAxis && key.data < NUM_AXES)
	{
		const char modifier = key.modifier == InputModifier::Negate ? '-' : '+';
		if (display)
			ret.format("Phone {} {}{}", key.source_index + 1, modifier, s_axis_display_names[key.data]);
		else
			ret.format("Phone-{}/{}{}", static_cast<u32>(key.source_index), modifier, s_axis_setting_names[key.data]);
	}
	else if (key.source_subtype == InputSubclass::ControllerButton && key.data < NUM_BUTTONS)
	{
		if (display)
			ret.format("Phone {} {}", key.source_index + 1, s_button_display_names[key.data]);
		else
			ret.format("Phone-{}/{}", static_cast<u32>(key.source_index), s_button_setting_names[key.data]);
	}

	return ret;
}

TinyString PhoneInputSource::ConvertKeyToIcon(InputBindingKey key)
{
	TinyString ret;
	if (key.source_type != InputSourceType::Phone)
		return ret;

	if (key.source_subtype == InputSubclass::ControllerAxis && key.data < NUM_AXES && key.modifier != InputModifier::FullAxis)
		ret.format("Phone {}  {}", key.source_index + 1, s_axis_icons[key.data][key.modifier == InputModifier::None]);
	else if (key.source_subtype == InputSubclass::ControllerButton && key.data < NUM_BUTTONS)
		ret.format("Phone {}  {}", key.source_index + 1, s_button_icons[key.data]);

	return ret;
}
