# ApolloVibe — Codebase Guide

This is **our fork of Apollo** (itself a Sunshine fork), built and released as **ApolloVibe** and
consumed by [MultiSeat](https://github.com/vibesoftwarecoder/MultiSeat). MultiSeat installs it to
`C:\Program Files\ApolloVibe\`, deliberately separate from any standalone `C:\Program Files\Apollo\`.

C++ / CMake / Ninja, MSVC on Windows. The web UI is Vite.

## Repo topology — get this right before committing

| remote | url | what it is |
|---|---|---|
| `origin` | `vibesoftwarecoder/Apollo` | **ours** — releases are published here |
| `upstream` | `ClassicOldSong/Apollo` | Apollo proper, by ClassicOldSong |
| `logabell` | `logabell/Apollo` | the microphone-passthrough fork |

**Work on `master`.** As of 2026-09-04 `master` and `apollovibe-dev` were collapsed into one
branch and are **identical**. `master` is the default branch, the branch releases are built from,
and the only branch GitHub reads issue templates from. `apollovibe-dev` is kept as a redundant
pointer for now; it carries nothing `master` lacks.

⛔ **Do not merge `logabell/feature/microphone-passthrough`.** That work is already absorbed;
merging it again re-applies changes that are in the tree.

⚠️ **`ClassicOldSong` is not `Nonary`.** Two different people, two different projects — Nonary
(Chase Payne) writes `libvirtualdisplay` and Vibeshine. Conflating them has produced wrong
conclusions before.

✅ **The old two-branch split is gone** (merge `a68da22a`). `master` previously carried 13 commits
of ours that a fast-forward would have destroyed — the ApolloVibe rebrand, version/update URLs, mic
lineage, AMD/BOOST fixes. Those are now on the single branch along with everything from
`apollovibe-dev`.

⚠️ **Still check `git rev-list --left-right --count` in BOTH directions before any merge advice.**
The rule outlived the specific divergence that produced it.

⚠️ **`upstream/master` has been dormant since 2026-05-21** and we are 0 behind it. If ClassicOldSong
resumes, merge often — the rebrand touches user-facing strings all over the tree, so conflicts scale
with how far behind you let it drift.

⛔ **Do not merge `logabell/master` either — it is 14 commits BEHIND ClassicOldSong**, so it drags
the tree backwards. `logabell/feature/microphone-passthrough` is 785 behind: stale, ignore it.

⚠️ **`%USERPROFILE%\Apollo-master` is NOT a git repo** — an unpacked source tree that looks like a
clone. The working repo is `Apollo-Development`.

Related forks under `vibesoftwarecoder`: `moonlight-common-c`, `moonlight-common-c-mic`; and
`MoonlightVibe-Development` tracks `logabell/moonlight-qt-mic`.

## Build and package

**Requires MSYS2** — the batch files run `ninja` through MSYS bash. Default `C:\msys64`,
overridable with `MSYS2_ROOT`. All four scripts are tracked (`72618f92`) and derive the repo root
from `%~dp0`, so they are portable.

```bat
build_apollovibe.bat            :: ninja -j4 sunshine  ->  build/sunshine.exe   (~187s)
build_apollovibe_rebase.bat     :: cmake configure + build, for after a rebase
package_apollovibe.bat <ver>    :: stages build/{sunshine.exe,assets,tools} into the release zip
```

Build output is gitignored (`38d1f013`): the zip, `_repackage/`, `build_apollovibe.log`.

⚠️ **These scripts once hardcoded `C:\Users\<username>\...`** and would have published a username to a
public fork. They were fixed before being committed, and reading them first is what caught it.
**Always read build tooling before committing it to a public repo** — absolute local paths hide
there.

### Deploying a build to this host

```
stop MultiSeatService   :: tears down seats and releases the exe lock
back up  C:\Program Files\ApolloVibe\sunshine.exe
copy the new sunshine.exe
start MultiSeatService
```

For a commit touching only `src/`, `sunshine.exe` is the only file that needs copying. The
standalone `C:\Program Files\Apollo\Sunshine.exe` keeps running throughout, which is correct.
Verify the deploy by a log line that only exists in the new build — a stale binary otherwise looks
identical.

### ⛔ The packaging trap that broke fresh installs

`build_apollovibe.bat` only **compiles**. CPack is NSIS-only here (`CPACK_BINARY_ZIP=OFF`), so the
portable zip is assembled by hand — and two releases shipped **`sunshine.exe` only**, with `assets/`
and `tools/` missing.

The symptom is nasty because it looks like a MultiSeat bug: Apollo exits at startup, MultiSeat's seat
provisioning fails, and the user reports "loopback RDP error" (this was GitHub issue #5).

`package_apollovibe.ps1` now hard-fails if `assets/apps.json`, `assets/web/index.html` or
`tools/sunshinesvc.exe` are missing. **Use it; never hand-zip a release.**

The release asset MultiSeat downloads is named `apollovibe-v<ver>-windows-x64.zip`, and the prereq
script currently pins **`v2026.6.1-multiseat.1`**. Changing the tag means changing
`install-prerequisites.ps1` too.

## Apollo internals worth knowing before you debug

These were learned the hard way while chasing MultiSeat issues; each one cost real time.

### `config::parse` runs BEFORE `logging::init`

```cpp
// src/main.cpp
if (config::parse(argc, argv)) { return 0; }   // ~line 162 — exits here
auto log_deinit_guard = logging::init(...);    // ~line 166 — logging starts HERE
```

So **a config failure exits with no log file at all.** If Apollo dies leaving nothing, look at
config, not at the encoder.

⚠️ But do **not** read the converse: a *healthy* Apollo can also log nothing if it cannot open its
log file. The signal is **whether the process stays alive**, never whether a log exists.

### FFmpeg is silenced unless the level is exactly `verbose`

```cpp
// src/logging.cpp
if (min_log_level >= 1) { av_log_set_level(AV_LOG_QUIET); }
else                    { av_log_set_level(AV_LOG_DEBUG); }
```

`verbose`=0, `debug`=1, `info`=2. **`debug` is not enough** — anything ≥ 1 discards every FFmpeg
message. Since `h264_amf`, the QSV encoders and the software encoders are all FFmpeg encoders, an
encoder that fails to open prints `Creating encoder [...]` and then **nothing**.

This is the single most useful setting when diagnosing an encoder.

### A failed encode device is silent by design

`make_synced_session` returns `std::nullopt` when `make_encode_device` yields null, **without
logging** — while every failure path inside the D3D11 encode-device setup does log. So a log that
stops right after `Creating encoder` means the encoder failed to open, not that Apollo crashed.

### `SUNSHINE_ASSETS_DIR` is a RELATIVE string on Windows

It is literally `"assets"` (`cmake/compile_definitions/common.cmake`), so `apply_config()` resolves
`assets/apps.json` against the **working directory**. MultiSeat runs each seat's Apollo with the
per-seat directory as its working dir, which is why it creates `assets` and `tools` junctions there.
Break the junction and the seat's Apollo dies before logging.

### Display capture is tied to the adapter that owns the output

`display_base.cpp` filters adapters by `adapter_name`, then enumerates **that adapter's** outputs and
requires `AttachedToDesktop` plus a successful DXGI duplication test. **The GPU follows the display**
— you cannot capture display X and encode on GPU Y.

### The SudoVDA message that explains MultiSeat issue #15

```
Warning: SudoVDA: display was added but never became nameable/active after 5100ms
         — RDP indirect display likely still owns the topology
```

Measured with a client attached: in a seat's RDP session the display namespace is **entirely
`RdpIdd_IndirectDisplay`** — 16 adapters, zero SudoVDA. The seat's display reports **1000 Hz**, which
is RdpIdd's synthetic rate and breaks frame pacing in older games. `ChangeDisplaySettingsEx` to 60 Hz
returns `DISP_CHANGE_SUCCESSFUL` and changes nothing.

So a seat streams its RDP surface. That works, and it is not a broken stream — but it is why seats
have no real refresh rate.

## Working on this host — safety rules

This machine is the reference host and runs live seats. These are not style preferences; each one
follows a real incident.

- ⛔ **The host is headless and the user is never physically at it.** Any procedure that says "watch
  the screen" or "listen to the speakers" cannot be run. Reach it over RustDesk or through logs.
- ⛔ **Never provision or tear down a seat while anything is streaming.** Check first, and check it
  correctly — Moonlight's video is UDP, so established TCP connections prove nothing. Use
  per-process GPU encode utilisation, which also names which Apollo is busy.
- ⛔ **Reboots are the user's call.** Stage them and say so; never run `Restart-Computer`.
- ⛔ **This fork is public.** Read anything before committing it, especially build tooling — these
  scripts once carried `C:\Users\<username>\...` and would have published a username.
- ⚠️ **Deploying a new `sunshine.exe` is manual, and a stale binary looks identical.** Verify with a
  log line only the new build emits.
- ⚠️ **Validate an instrument before trusting what it says.** A probe that returns the same answer
  no matter what you change is broken, not informative — run it where you *know* the answer first.

Fuller versions of these, and the incidents behind them, are in this project's memory.

## Testing changes against MultiSeat

MultiSeat is the main consumer, so a change here is not proven until a seat uses it:

```powershell
# in the MultiSeat repo
.\scripts\smoke-seat.ps1 -Account <seat>      # provision, assert, tear down, restore
```

⛔ **Never provision or tear down a seat while someone is streaming.** Teardown makes a standalone
console Apollo rebuild its encoder (~700 ms stall, measured five times). Check first with
per-process GPU encode utilisation — **not** established TCP connections, since Moonlight's video is
UDP:

```powershell
(Get-Counter '\GPU Engine(*engtype_VideoEncode)\Utilization Percentage').CounterSamples |
  Where-Object CookedValue -gt 1
```
