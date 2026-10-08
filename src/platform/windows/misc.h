/**
 * @file src/platform/windows/misc.h
 * @brief Miscellaneous declarations for Windows.
 */
#pragma once

// standard includes
#include <chrono>
#include <functional>
#include <string_view>

// platform includes
#include <Windows.h>
#include <winnt.h>

// local includes
#include "src/input_desktop_wait.h"

namespace platf {
  void print_status(const std::string_view &prefix, HRESULT status);

  /**
   * @brief Make this thread use the current input desktop.
   * @param last_error If not null, receives the Win32 error on failure, ERROR_SUCCESS on success.
   * @return The desktop now assigned to the thread, or nullptr if the input desktop could not be
   *         opened (for example ACCESS_DENIED while the Winlogon desktop is active) or assigned. On
   *         nullptr the thread keeps the desktop it had. The handle is owned by this module.
   */
  HDESK syncThreadDesktop(DWORD *last_error = nullptr);

  /**
   * @brief Check whether the input desktop can currently be opened. Opens and closes it, assigns
   *        nothing to the thread and logs nothing.
   * @param last_error If not null, receives the Win32 error on failure, ERROR_SUCCESS on success.
   */
  bool input_desktop_accessible(DWORD *last_error = nullptr);

  /**
   * @brief Start and stop the desktop-switch listener once.
   * @return true if the EVENT_SYSTEM_DESKTOPSWITCH hook could be installed on this thread's desktop.
   *         False means waits fall back to polling only. Also proves the listener thread starts and
   *         stops cleanly.
   */
  bool desktop_switch_hook_available();

  /**
   * @brief Wait for the input desktop to become accessible (initial capture start only).
   * @details Returns at once when it already is. Otherwise waits on desktop-switch events with
   *          polling as the backstop, until it opens, `timeout` expires or `cancelled` returns true.
   * @param timeout Longest wait. Zero or less returns immediately without probing.
   * @param cancelled Polled during the wait; return true to abandon it (shutdown).
   */
  input_desktop_wait_result_t await_input_desktop(std::chrono::milliseconds timeout, const std::function<bool()> &cancelled);


  int64_t qpc_counter();

  std::chrono::nanoseconds qpc_time_difference(int64_t performance_counter1, int64_t performance_counter2);

  /**
   * @brief Convert a UTF-8 string into a UTF-16 wide string.
   * @param string The UTF-8 string.
   * @return The converted UTF-16 wide string.
   */
  std::wstring from_utf8(const std::string_view &string);

  /**
   * @brief Convert a UTF-16 wide string into a UTF-8 string.
   * @param string The UTF-16 wide string.
   * @return The converted UTF-8 string.
   */
  std::string to_utf8(const std::wstring_view &string);
}  // namespace platf
