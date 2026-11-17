# Recorded session, 2026-11-17

One run, recorded end to end over the Flipper RPC interface: the screen was
captured from the device framebuffer while the same process drove the keys, so
the pictures and the logs below come from the same pass, in order.

Setup: stock firmware `a4277e5a…` on the ESP32-S2 devboard, app built from
commit `027ec70`, empty `params.txt` (no address pinned, auto discovery), one
Netgear CG3000DV2C0 on channel 11 with its SSID hidden.

The scan saw 99 other networks. Their names and addresses are censored here:
list rows in the screens and frames are blanked with a bar, and `trace.txt`
shows `[redacted]` in place of their SSIDs and BSSIDs. The target's own values
are untouched, and the bars start after the row marker so the cursor, channel,
RSSI and `*` vulnerability flag stay readable.

| time | event |
| --- | --- |
| 05:22:52 | scan started |
| 05:23:34 | target row selected, dump started |
| 05:32:17 | `DUMP RESULT 0`, passphrase written to `found.txt` |

The dump took 8m43s. The session made 23 associations, 87 fragment ACKs and 4
real leak frames; that was enough for the config block to land in the capture
window.

## Screens

`screens/` holds the framebuffer as captured, 2× for legibility:

| file | state |
| --- | --- |
| `01-launch.png` | app start screen |
| `02-scanning.png`, `03-scanning-late.png` | live scan, APs appearing as `L` records arrive |
| `04-targets.png` | result list, `*` marks WPS + Broadcom fingerprint |
| `05-target-selected.png` | cursor on the hidden AP |
| `06-dump-start.png` | dump start |
| `07-dump-channel.png`, `08-dump-frag-sent.png`, `09-dump-assoc-ok.png` | stage line during the overflow |
| `10-password-found.png` | result screen |

`run.gif` is the whole sequence at 600 ms per frame.

`frames.txt` lists every captured frame as index, capture time and label, so a
frame can be matched to the trace by the wall clock.

## Logs

| file | contents |
| --- | --- |
| `trace.txt` | full stage trace for the run, 42 KB, one `V <stage> <code> <len> <hex>` record per event; non-target APs appear as `[redacted]` |
| `capture.bin` | the 2 KB heap window around the recovered credential, as `C <chunk> <len> <bytes>` records |
| `capture-window.hexdump.txt` | that archive decoded, 161 lines |
| `leaks.bin` | the four leaked slices from the session, `L <slice> <len> <bytes>` |
| `leaks.hexdump.txt` | those slices decoded |
| `found.txt` | the app's own result file |

## What the memory window contains

The window is the BSS configuration block. Three C strings in one allocation:

```
000002b0  43 47 33 30 30 30 44 56 32 43 30 00 00 00 00 00  CG3000DV2C0.....
000002d0  00 57 50 41 32 2d 50 53 4b 00 00 00 00 00 00 00  .WPA2-PSK.......
000002e0  00 00 00 00 00 00 43 47 33 30 30 30 44 56 32 41  ......CG3000DV2A
000002f0  41 32 42 43 30 00 00 00 00 00 00 00 00 00 00 00  A2BC0...........
```

- `0x2b0` — the SSID the beacon hides
- `0x2d1` — `WPA2-PSK`
- `0x2d6` — the 15-character passphrase

The offsets are relative to the start of the window, not to an absolute
address; the allocation moves between boots, which is why the window is
archived rather than an address.
