/**
 * @file tests/unit/test_input_desktop_wait.cpp
 * @brief Test src/input_desktop_wait.h, the wait for the input desktop at capture start.
 * @details The loop is driven with a fake clock and a fake desktop, so these tests check timing and
 *          decisions exactly: how long it waited, how often it probed, what ended the wait.
 */
#include "../tests_common.h"

#include <src/input_desktop_wait.h>

#include <vector>

#ifdef _WIN32
  #include <src/platform/windows/misc.h>
#endif

using namespace std::chrono_literals;
using platf::input_desktop_wait_outcome_e;

namespace {
  constexpr unsigned long access_denied = 5;

  /// A desktop that opens at `open_at` (never, if negative) on a clock the wait itself advances.
  struct fake_world_t {
    std::chrono::milliseconds t {0};
    std::chrono::milliseconds open_at {-1};
    std::chrono::milliseconds signal_at {-1};  ///< When a desktop-switch event fires (negative: never).
    std::chrono::milliseconds cancel_at {-1};  ///< When the caller cancels (negative: never).
    std::vector<std::chrono::milliseconds> slices;
    unsigned probe_calls = 0;
    unsigned failure_calls = 0;
    unsigned long failure_error = 0;
    unsigned progress_calls = 0;

    platf::input_desktop_wait_result_t run(std::chrono::milliseconds timeout, std::chrono::milliseconds poll = 250ms) {
      platf::input_desktop_wait_options_t options;
      options.timeout = timeout;
      options.poll_interval = poll;
      return platf::wait_for_input_desktop(
        options,
        [&](unsigned long &error) {
          ++probe_calls;
          if (open_at >= 0ms && t >= open_at) {
            return true;
          }
          error = access_denied;
          return false;
        },
        [&](std::chrono::milliseconds slice) {
          slices.push_back(slice);
          if (signal_at > t && signal_at <= t + slice) {
            t = signal_at;
            return true;
          }
          t += slice;
          return false;
        },
        [&]() {
          return cancel_at >= 0ms && t >= cancel_at;
        },
        [&]() {
          return t;
        },
        [&](unsigned long error) {
          ++failure_calls;
          failure_error = error;
        },
        [&](std::chrono::milliseconds, unsigned long) {
          ++progress_calls;
        }
      );
    }
  };
}  // namespace

TEST(InputDesktopWait, ZeroTimeoutDoesNothing) {
  fake_world_t w;
  w.open_at = 5s;
  auto r = w.run(0ms);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::disabled);
  EXPECT_TRUE(r.accessible());
  EXPECT_EQ(w.probe_calls, 0u) << "timeout 0 must restore the old behaviour: no probe, no wait";
  EXPECT_TRUE(w.slices.empty());
}

TEST(InputDesktopWait, AccessibleDesktopStartsWithoutDelay) {
  fake_world_t w;
  w.open_at = 0ms;
  auto r = w.run(180s);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::ready_immediately);
  EXPECT_EQ(r.probes, 1u);
  EXPECT_EQ(r.waited, 0ms);
  EXPECT_TRUE(w.slices.empty()) << "a normal start must not sleep at all";
  EXPECT_EQ(w.failure_calls, 0u);
}

TEST(InputDesktopWait, PollingFindsDesktopWhenNoEventEverFires) {
  fake_world_t w;
  w.open_at = 31s;  // the documented 30 s Winlogon period, plus a little
  auto r = w.run(180s);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::ready_after_wait);
  EXPECT_EQ(r.signal_wakeups, 0u);
  EXPECT_EQ(r.waited, 31s);
  EXPECT_EQ(w.failure_calls, 1u);
  EXPECT_EQ(w.failure_error, access_denied);
  EXPECT_EQ(w.progress_calls, 3u) << "progress is reported every 10 s while waiting";
}

TEST(InputDesktopWait, DesktopSwitchEventWakesTheWaitBeforeThePollIntervalEnds) {
  fake_world_t w;
  w.open_at = 1234ms;
  w.signal_at = 1234ms;
  // Poll interval of 60 s: only the event can explain finding the desktop at 1234 ms.
  auto r = w.run(180s, 60s);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::ready_after_wait);
  EXPECT_EQ(r.signal_wakeups, 1u);
  EXPECT_EQ(r.waited, 1234ms);
  EXPECT_EQ(r.probes, 2u);
}

TEST(InputDesktopWait, EventForAnotherSwitchDoesNotEndTheWaitEarly) {
  fake_world_t w;
  w.open_at = 5s;
  w.signal_at = 1s;  // a switch that does not make the desktop accessible
  auto r = w.run(180s);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::ready_after_wait);
  EXPECT_EQ(r.signal_wakeups, 1u);
  EXPECT_EQ(r.waited, 5s);
}

TEST(InputDesktopWait, TimesOutAtTheLimitAndNotLater) {
  fake_world_t w;  // never opens
  auto r = w.run(2s, 750ms);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::timed_out);
  EXPECT_FALSE(r.accessible());
  EXPECT_EQ(r.waited, 2s) << "the last slice must be shortened so the wait does not overshoot";
  EXPECT_EQ(r.last_error, access_denied);
  for (auto slice : w.slices) {
    EXPECT_LE(slice, 750ms);
  }
}

TEST(InputDesktopWait, DesktopThatOpensAtTheDeadlineIsStillFound) {
  fake_world_t w;
  w.open_at = 2s;
  auto r = w.run(2s, 750ms);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::ready_after_wait) << "one last probe must run after the final sleep";
}

TEST(InputDesktopWait, CancellationEndsTheWaitWithinOnePollInterval) {
  fake_world_t w;  // never opens
  w.cancel_at = 600ms;
  auto r = w.run(180s, 250ms);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::cancelled);
  EXPECT_FALSE(r.accessible());
  EXPECT_LE(r.waited, 600ms + 250ms);
}

TEST(InputDesktopWait, CancelledBeforeStartNeverProbes) {
  fake_world_t w;
  w.open_at = 0ms;
  w.cancel_at = 0ms;
  auto r = w.run(180s);
  EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::cancelled);
  EXPECT_EQ(w.probe_calls, 0u);
}

#ifdef _WIN32
TEST(InputDesktopWaitWindows, MatchesTheRealDesktopState) {
  DWORD error = 0;
  const bool accessible = platf::input_desktop_accessible(&error);
  const auto start = std::chrono::steady_clock::now();
  auto r = platf::await_input_desktop(1500ms, []() {
    return false;
  });
  const auto took = std::chrono::steady_clock::now() - start;

  if (accessible) {
    EXPECT_EQ(r.outcome, input_desktop_wait_outcome_e::ready_immediately);
    EXPECT_LT(took, 1s) << "an accessible desktop must not delay the start";
  } else {
    // Only reachable when the tests run on a locked or secure desktop.
    EXPECT_NE(r.outcome, input_desktop_wait_outcome_e::ready_immediately);
    EXPECT_GE(took, 1400ms);
  }
}

TEST(InputDesktopWaitWindows, ZeroTimeoutAndCancelReturnAtOnce) {
  auto start = std::chrono::steady_clock::now();
  EXPECT_EQ(platf::await_input_desktop(0ms, []() {
              return false;
            }).outcome,
            input_desktop_wait_outcome_e::disabled);
  EXPECT_EQ(platf::await_input_desktop(180s, []() {
              return true;
            }).outcome,
            input_desktop_wait_outcome_e::cancelled);
  EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
}

TEST(InputDesktopWaitWindows, DesktopSwitchListenerStartsAndStopsCleanly) {
  // Each call starts the hook thread, installs the hook, runs its message loop and joins it.
  // A hang here would be a shutdown deadlock; the result only says whether events can be heard.
  bool installed = false;
  for (int i = 0; i < 5; ++i) {
    installed = platf::desktop_switch_hook_available();
  }
  std::cout << "desktop switch hook installed on this host: " << (installed ? "yes" : "no") << std::endl;
  SUCCEED();
}
#endif
