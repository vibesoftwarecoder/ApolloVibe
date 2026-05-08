/**
 * @file src/rtsp.h
 * @brief Declarations for RTSP streaming.
 */
#pragma once

// standard includes
#include <atomic>
#include <memory>
#include <list>

// local includes
#include "crypto.h"
#include "thread_safe.h"

#ifdef _WIN32
  #include <windows.h>
#endif

// Resolve circular dependencies
namespace stream {
  struct session_t;
}

namespace rtsp_stream {
  // Use offset 26 (port 48010 with default sunshine.port=47984) — this matches
  // Sunshine's stock RTSP port, which some clients (notably Moonlight iOS over
  // Tailscale) appear to treat as well-known. Offset 21 (port 48005) saw zero
  // SYN arrivals from iOS clients while 47979/47984 worked, suggesting iOS
  // Tailscale silently drops/doesn't route packets to non-canonical ports.
  constexpr auto RTSP_SETUP_PORT = 26;

  struct launch_session_t {
    uint32_t id;

    crypto::aes_t gcm_key;
    crypto::aes_t iv;

    std::string av_ping_payload;
    uint32_t control_connect_data;

    std::string device_name;
    std::string unique_id;
    crypto::PERM perm;

    bool input_only;
    bool host_audio;
    bool enable_mic;
    int width;
    int height;
    int fps;
    int gcmap;
    int surround_info;
    std::string surround_params;
    bool enable_hdr;
    bool enable_sops;
    bool virtual_display;
    uint32_t scale_factor;

    std::optional<crypto::cipher::gcm_t> rtsp_cipher;
    std::string rtsp_url_scheme;
    uint32_t rtsp_iv_counter;

    std::list<crypto::command_entry_t> client_do_cmds;
    std::list<crypto::command_entry_t> client_undo_cmds;

  #ifdef _WIN32
    GUID display_guid{};
  #endif
  };

  void launch_session_raise(std::shared_ptr<launch_session_t> launch_session);

  /**
   * @brief Clear state for the specified launch session.
   * @param launch_session_id The ID of the session to clear.
   */
  void launch_session_clear(uint32_t launch_session_id);

  /**
   * @brief Get the number of active sessions.
   * @return Count of active sessions.
   */
  int session_count();

  std::shared_ptr<stream::session_t>
  find_session(const std::string_view& uuid);

  std::list<std::string>
  get_all_session_uuids();

  /**
   * @brief Terminates all running streaming sessions.
   */
  void terminate_sessions();

  /**
   * @brief Runs the RTSP server loop.
   */
  void start();
}  // namespace rtsp_stream
