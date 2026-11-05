# ApolloVibe

> ## About this fork — ApolloVibe
>
> **ApolloVibe** is our fork of [Apollo](https://github.com/ClassicOldSong/Apollo) by
> ClassicOldSong, which is itself a Sunshine fork. It is built and released here, and installed to
> `C:\Program Files\ApolloVibe` by
> [MultiSeat](https://github.com/vibesoftwarecoder/MultiSeat) — deliberately separate from a
> standalone Apollo install, so the two can coexist.
>
> **Where to report a problem:**
>
> | what is wrong | where it goes |
> |---|---|
> | Streaming, encoding, capture, host audio or input in ApolloVibe | **here** |
> | The client: seat discovery, gamepad, microphone passthrough | [MoonlightVibe](https://github.com/vibesoftwarecoder/MoonlightVibe/issues) |
> | A seat will not provision, or a seat streams the wrong desktop | [MultiSeat](https://github.com/vibesoftwarecoder/MultiSeat/issues) |
>
> A failure that looks like a MultiSeat provisioning bug is often an ApolloVibe one, so if you are
> unsure, file it either way and we will move it.
>
> **Problems that turn out to come from upstream Apollo still belong here.** If a fix belongs
> upstream we will take it there ourselves — working out whose code it is is our job, not yours.


**ApolloVibe** is a Windows game streaming host. It is built for [MultiSeat](https://github.com/vibesoftwarecoder/MultiSeat), which runs several Moonlight streaming sessions on one machine, and it also works on its own.

It is a fork of [ClassicOldSong/Apollo](https://github.com/ClassicOldSong/Apollo). The microphone passthrough patches from [logabell](https://github.com/logabell/Apollo) are rebased onto it, and this fork adds the features in the table below.

---

## What's different from upstream Apollo

| Feature | ApolloVibe | Upstream Apollo |
|---|---|---|
| Microphone passthrough | ✅ `stream_mic = enabled`, played into the Steam Streaming Microphone | ❌ Not available |
| Second video stream | ✅ A second picture in the same session: one host window, or a whole display the host makes. Off by default | ❌ Not available |
| USB forwarding | ✅ A paired client can share a USB device with the host. Experimental, off by default | ❌ Not available |
| Multi-instance isolation | ✅ `file_state` is written per seat, so each instance has its own UUID | ⚠️ All instances share the UUID by default |
| MultiSeat auto-config | ✅ MultiSeat generates the config for each seat | Manual |
| Branding | ApolloVibe | Apollo |

Everything else is inherited from ClassicOldSong/Apollo: virtual displays, NVENC, AMF and AV1 encoding, HDR, the permission system, clipboard sync and controller input.

---

## Download

Get the latest release from the [Releases page](https://github.com/vibesoftwarecoder/ApolloVibe/releases/latest).

> **Using MultiSeat?** You don't need to install ApolloVibe by hand. The MultiSeat prerequisites script downloads and installs it for you.

---

## Usage with MultiSeat

MultiSeat manages ApolloVibe completely. Each seat gets its own ApolloVibe process, config folder, port range and state file, so there is nothing to set up by hand.

See the [MultiSeat README](https://github.com/vibesoftwarecoder/MultiSeat) for the full setup.

## Usage on its own

ApolloVibe is a drop-in replacement for Apollo. The config format is the same, so the [Sunshine documentation](https://docs.lizardbyte.dev/projects/sunshine) applies. The options this fork adds are in [docs/configuration.md](docs/configuration.md).

---

## Second video stream

A session can carry a second picture next to the first. A client that supports it, such as [MoonlightVibe](https://github.com/vibesoftwarecoder/MoonlightVibe), shows the two in two windows. The second picture is one of two things:

- **A window.** The host captures one window, picked by its title. It follows the window if it moves, raises it when the stream starts, and ends the stream if the window stays gone for `capture_window_wait_timeout` seconds.
- **A whole display.** The host makes a virtual display of the size the client asked for, and captures it. Windows you drag onto it show up in the second picture. The host removes the display when the second stream ends.

Turn it on in the config:

```
second_video_stream = enabled
```

Where each kind works:

| Where the host runs | A window | A whole display |
|---|---|---|
| The console session (the main desktop) | ✅ | ✅ |
| A MultiSeat seat | ✅ | ❌ The client gets one stream |

A seat cannot make a display because its remote-desktop session belongs to the remote-desktop display driver, and Windows will not let a new display join it. On a seat, choose a window.

The second stream uses its own capture thread and encoder, so it never interrupts the first. With the setting off, which is the default, a session is exactly as it was. A client that does not ask for it never notices.

## Microphone passthrough

ApolloVibe takes Opus microphone packets from a compatible client, decodes them on the host and plays them into `Speakers (Steam Streaming Microphone)`. Applications should pick `Microphone (Steam Streaming Microphone)` as their input.

Turn it on with `stream_mic = enabled`. It needs a compatible client, and [MoonlightVibe](https://github.com/vibesoftwarecoder/MoonlightVibe) is the recommended one.

## USB forwarding (experimental)

A paired client can share one of its USB devices with this host, which then sees it as if it were plugged in. It is off by default and Windows only. It needs the `usbip-win2` driver on the host, the setting `usb_forwarding_enabled = enabled`, and the USB permission granted to the client in the client list.

Read the warning in [docs/configuration.md](docs/configuration.md) before you turn it on. Giving a client this permission is the same as giving it physical USB access.

## Multi-instance support

Every ApolloVibe instance needs its own `file_state` path. Without one, all instances share the same UUID and Moonlight treats them as the same server. If you run several instances by hand, add this to each instance's `sunshine.conf`:

```
file_state = C:\path\to\this-instance\config\sunshine_state.json
```

MultiSeat does this for you.

---

## Building

ApolloVibe builds the same way as ClassicOldSong/Apollo: **MSYS2 UCRT64** with GCC, Ninja and pkg-config. MSVC is not supported.

```bash
# In an MSYS2 UCRT64 terminal
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

See [ClassicOldSong/Apollo](https://github.com/ClassicOldSong/Apollo) for the full dependency list.

---

## License

ApolloVibe is licensed under the same terms as Sunshine — [GPL-3.0](LICENSE).

Microphone passthrough patches by [logabell](https://github.com/logabell/Apollo), rebased and maintained here.
