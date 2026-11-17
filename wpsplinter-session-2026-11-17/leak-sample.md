# Leak archive sample

Five 16-byte slices the overflow returned from a Broadcom registrar's heap,
captured on a Netgear CG3000DV2C0 (BCM3380-class, `Wl Ver 6.37.14.87`). The
archive is written by the app as `/ext/apps_data/wpsplinter/leaks.bin` and
decoded with `decode_leaks.py`.

```
00000000  01 10 49 00 06 00 37 2a 00 01 20 dd 0b 00 14 6c  ..I...7*.. ....l
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000020  76 69 61 72 43 6f 32 30 32 32 01 08 82 84 8b 96  [redacted]......
00000030  fc 0b 71 50 95 92 5a 6d ec df e0 15 59 1e a1 f1  ..qP..Zm........
00000040  20 73 79 6d 62 6f 6c 20 74 69 6d 69 6e 67 3b 43   symbol timing;C
```

The hexdump is the slices concatenated in capture order. The record indexes
they were archived under (`L000`, `L001`, `L007`, `L015`, `L023`) are the leak
rounds, which is why the last three bytes of one round and the first of the
next are unrelated allocations. The readable runs are neighbouring heap
objects: an SSID (`[redacted]`), the start of a WSC TLV header
(`01 10 49 00 ...`, attribute 0x1049), and another allocation's text
(`symbol timing;C`).

These slices are not the credential itself; they are the heap the credential
was read out of. The key is recovered from a 2 KB capture window and appears
in `capture.bin` when the run finds one.
