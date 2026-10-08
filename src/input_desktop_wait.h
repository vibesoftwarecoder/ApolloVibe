/**
 * @file src/input_desktop_wait.h
 * @brief Platform-neutral wait loop for the input desktop to become accessible.
 * @details In a freshly created Windows session the Winlogon (secure) desktop is the input
 *          desktop until the shell is ready, or for up to about 30 seconds, and it can stay
 *          that way much longer while a lock screen or credential prompt is up. A process that
 *          is not SYSTEM gets ACCESS_DENIED from OpenInputDesktop during that time, so display
 *          capture cannot start. The loop here waits for that to end. The Windows-specific pieces
 *          (the probe, the desktop-switch signal) are injected, so the logic itself is tested
 *          without a desktop.
 */
#pragma once

// standard includes
#include <algorithm>
#include <chrono>
#include <cstdint>

namespace platf {

  /// How an input desktop wait ended.
  enum class input_desktop_wait_outcome_e {
    disabled,  ///< The timeout was zero, so nothing was probed or waited for.
    ready_immediately,  ///< The first probe succeeded; no waiting happened.
    ready_after_wait,  ///< The desktop became accessible while waiting.
    timed_out,  ///< The timeout expired with the desktop still inaccessible.
    cancelled,  ///< The caller asked to stop (shutdown) before the desktop became accessible.
  };

  /// What a wait did, for logging and for tests.
  struct input_desktop_wait_result_t {
    input_desktop_wait_outcome_e outcome = input_desktop_wait_outcome_e::disabled;
    std::chrono::milliseconds waited {0};  ///< Time from the first probe to the end.
    unsigned probes = 0;  ///< How many times the probe ran.
    unsigned signal_wakeups = 0;  ///< Waits that ended because the desktop-switch signal fired.
    unsigned long last_error = 0;  ///< The probe's error code from its last failure, 0 if none.

    /// @return true if the caller may go on to open the input desktop.
    [[nodiscard]] bool accessible() const {
      return outcome == input_desktop_wait_outcome_e::ready_immediately ||
             outcome == input_desktop_wait_outcome_e::ready_after_wait ||
             outcome == input_desktop_wait_outcome_e::disabled;
    }
  };

  /// Tuning for the wait loop.
  struct input_desktop_wait_options_t {
    std::chrono::milliseconds timeout {0};  ///< Longest total wait. Zero disables the wait.
    std::chrono::milliseconds poll_interval {250};  ///< Longest single sleep; the polling backstop.
    std::chrono::milliseconds progress_interval {10000};  ///< How often on_progress runs while waiting.
  };

  /**
   * @brief Wait until the input desktop can be opened, the timeout expires, or the caller cancels.
   * @details The probe runs first, so a desktop that is already accessible costs one probe and no
   *          sleep. Otherwise the loop sleeps in slices of at most `poll_interval`. A slice ends
   *          early when `wait_for_signal` reports that the desktop-switch event fired, so the
   *          probe re-runs at once. If that signal never fires (hook unavailable, wrong desktop),
   *          the slices still elapse and the probe still runs: polling is the backstop, the event
   *          only makes it faster. After the final slice the probe runs once more before the
   *          timeout is declared, so a desktop that opens at the last moment is not missed.
   * @param options Timeout and intervals.
   * @param probe `bool(unsigned long &error)`: true if the input desktop can be opened, otherwise
   *        false with the Win32 error in `error`. Must not log on failure; the loop owns the logging.
   * @param wait_for_signal `bool(std::chrono::milliseconds)`: block up to the given time, return
   *        true if woken by the desktop-switch signal, false on a plain timeout.
   * @param cancelled `bool()`: true if the caller wants the wait abandoned. Checked before every
   *        probe and after every sleep, so cancellation latency is at most `poll_interval`.
   * @param now `std::chrono::milliseconds()`: a monotonic clock.
   * @param on_failure `void(unsigned long error)`: runs once, on the first failed probe.
   * @param on_progress `void(std::chrono::milliseconds waited, unsigned long error)`: runs every
   *        `progress_interval` while the wait goes on.
   */
  template<class Probe, class WaitForSignal, class Cancelled, class Now, class OnFailure, class OnProgress>
  input_desktop_wait_result_t wait_for_input_desktop(
    const input_desktop_wait_options_t &options,
    Probe &&probe,
    WaitForSignal &&wait_for_signal,
    Cancelled &&cancelled,
    Now &&now,
    OnFailure &&on_failure,
    OnProgress &&on_progress
  ) {
    using ms = std::chrono::milliseconds;
    input_desktop_wait_result_t result;

    if (options.timeout <= ms::zero()) {
      return result;  // outcome == disabled
    }

    const auto start = now();
    auto next_progress = options.progress_interval;
    const auto poll = std::max(options.poll_interval, ms {1});

    auto finish = [&](input_desktop_wait_outcome_e outcome) {
      result.outcome = outcome;
      result.waited = now() - start;
      return result;
    };

    for (;;) {
      if (cancelled()) {
        return finish(input_desktop_wait_outcome_e::cancelled);
      }

      unsigned long error = 0;
      ++result.probes;
      if (probe(error)) {
        return finish(result.probes == 1 ? input_desktop_wait_outcome_e::ready_immediately : input_desktop_wait_outcome_e::ready_after_wait);
      }
      if (result.probes == 1) {
        on_failure(error);
      }
      result.last_error = error;

      const auto elapsed = now() - start;
      if (elapsed >= options.timeout) {
        return finish(input_desktop_wait_outcome_e::timed_out);
      }

      if (elapsed >= next_progress) {
        on_progress(elapsed, error);
        next_progress = elapsed + options.progress_interval;
      }

      const auto slice = std::min(poll, options.timeout - elapsed);
      if (wait_for_signal(slice)) {
        ++result.signal_wakeups;
      }
    }
  }

}  // namespace platf
