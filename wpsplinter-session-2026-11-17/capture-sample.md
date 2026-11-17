# Capture windows

Once the credential scan hits, the firmware streams the 2 KB of heap around it
to the Flipper, and the app writes those bytes to
`/ext/apps_data/wpsplinter/capture.bin` as `C <chunk> <len> <bytes>` records.
`./decode_leaks.py capture.bin --ascii` turns the archive back into memory.

A full recorded run, with screen captures and the raw logs from the same pass,
is in [`session-2026-11-17/`](session-2026-11-17/README.md). It was taken with
no `params.txt` and no address pinned, on a Netgear CG3000DV2C0
(BCM3380-class, `Wl Ver 6.37.14.87`, CFE `2.4.0beta1R8`).

The window is that device's BSS configuration block, not a WSC attribute: the
hidden SSID, the authentication string and the passphrase are three C strings
in a single allocation.

```
000002b0  43 47 33 30 30 30 44 56 32 43 30 00 00 00 00 00  CG3000DV2C0.....
000002d0  00 57 50 41 32 2d 50 53 4b 00 00 00 00 00 00 00  .WPA2-PSK.......
000002e0  00 00 00 00 00 00 43 47 33 30 30 30 44 56 32 41  ......CG3000DV2A
000002f0  41 32 42 43 30 00 00 00 00 00 00 00 00 00 00 00  A2BC0...........
```

- `0x2b0` — the SSID the beacon hides
- `0x2d1` — `WPA2-PSK`
- `0x2d6` — the 15-character passphrase

That is the shape `find_bss_credential()` looks for: the `WPA2-PSK` marker
followed within 64 bytes by a printable run of 8 to 63 characters that is not
itself a cipher name. The window is archived before that scan runs, so these
are the registrar's bytes as read, not a reconstruction.

The offsets are relative to the window. The allocation lands somewhere else on
the next boot — the same block appeared at `0x340`, `0x628` and `0x2b0` on
three different boots — which is why the window is kept rather than an
address.
