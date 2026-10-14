# Test equipment: the simulated PLC and the test controller

**Nothing in this directory is part of the gateway.** These two programs exist only to exercise the gateway in the
demo:

- `mb_plc_sim.c`: a simulated PLC for a small water works, a Modbus/TCP server on 127.0.0.1:1502. It enforces
  nothing itself; it obeys every request that reaches it and logs every write.
- `mb_demo_master.c`: the scripted test controller. It plays `../demo/script.txt` against the gateway and records
  what comes back.

To build them, see `../build/README.md`.

## libmodbus

Both programs are built on **libmodbus 3.2.0**, commit a9b025d, https://github.com/stephane/libmodbus.

- **Licence:** GNU Lesser General Public License, version 2.1 or later (SPDX: LGPL-2.1-or-later). The full text is
  `libmodbus/COPYING.LESSER`; the authors are listed in `libmodbus/AUTHORS`.
- **Unmodified:** `libmodbus/src/` is byte-identical to the upstream commit. The only addition is a hand-written
  Linux `config.h` (in `../build/`), because the upstream autotools build was not used.
- **Linked statically** into the two programs. Their own source is here and the build file is
  `../build/Makefile.linux`, so you can rebuild or relink them against a modified libmodbus.
- **Never part of the gateway.** The gateway's programs (`../src/`) and proven cores (`../proofs/`) contain no
  libmodbus code. They were specified from the public Modbus specifications (Modbus Application Protocol V1.1b3 and
  Modbus Messaging on TCP/IP Implementation Guide V1.0b).

The two programs' own source (`mb_plc_sim.c`, `mb_demo_master.c`) is The Dark Factory's, under the MIT licence in
`../LICENSE`. The libmodbus directory stays under its own licence.
