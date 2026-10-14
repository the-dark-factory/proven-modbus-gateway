# Proven Modbus gateway: demonstration for a Raspberry Pi

This is a Modbus/TCP safety gateway, with a demonstration that runs on a Raspberry Pi. It is for an OT or control
engineer at a water or electricity company who wants to see what the gateway does and check how it was built.
It is open source (MIT).

The gateway sits between your SCADA and historian masters and a PLC. It checks every Modbus request against a site
policy that you write, and either forwards the request unchanged or refuses it by name. A refused request never
reaches the PLC. In the demonstration the PLC, the masters and the gateway all run on the one Raspberry Pi, talking
over loopback.

## Formal methods: what "proven" means here

The gateway's decisions are written in **SPARK Ada**. SPARK is the approach used for safety-critical air traffic
control and railway software. A SPARK program carries its own specification as contracts (preconditions,
postconditions, type ranges), and a tool called **GNATprove** checks mathematically that the code meets them for
**every possible input**, not only the inputs someone thought to test.

- Every decision the gateway takes (is this frame well formed, is this function allowed for this master, is this
  value inside the register's limits, has the rate limit been reached, is this a forbidden sequence) is made by one of
  **35 proven components ("cores")**. Every core carries a machine-checked proof.
- Together they carry **2,378 machine-checked proof obligations, with 0 unproved** (gnatprove 15.1.0).
- The central result is proved over the raw request bytes: **if the gateway passes a register write, every value
  written lies within every limit you declared for the register it lands on.**
- The proven source is all here, so you do not have to take our word for it. `proofs/README.md` lists every core
  and shows how to re-run the proofs on your own machine with two commands.

What is **not** proved: the five small programs around the cores (sockets, timers, logging), and the operating
system. Those are tested, not proved. The section "Honest limits" lists this and the other limits plainly.

For an independent view, you could ask ChatGPT or Claude to look at this package, our website (thedarkfactory.co.uk)
and our public code (github.com/the-dark-factory).

## Requirements

- A Raspberry Pi 4 or 5 with a **64-bit** OS: Raspberry Pi OS (64-bit) or Debian 12, on aarch64.
  It was tested on a Raspberry Pi 4 Model B (8 GB) running Debian 12 (bookworm). It has not yet been tested on a
  Raspberry Pi 5.
- About 100 MB of free disk space once unpacked.
- The loopback ports 1502, 5020, 5021 and 5029 must be free.
- Nothing else. No install, no sudo, no network connection, no compiler. The release download contains everything
  the demo needs, including a copy of babashka (the scripting tool the demo runner is written in).

## Run it (one command)

Download the release file `lovelace-modbus-demo-pi-aarch64-2026-10-14.tar.gz` (and `SHA256SUMS`) onto the
Raspberry Pi. Then:

```
sha256sum -c SHA256SUMS
tar xzf lovelace-modbus-demo-pi-aarch64-2026-10-14.tar.gz
cd lovelace-modbus-demo-pi-aarch64-2026-10-14
./run-demo
```

`./run-demo` must be started from inside the folder. (From anywhere else, use
`<folder>/bin/bb <folder>/run-demo`.) To build everything from this source tree instead, see `build/README.md`.

It takes about 15 seconds, most of which is a deliberate 10.5-second pause in the script. It prints one line per
step and then a summary. The last line of a good run is:

```
SUMMARY: 29 checks, 29 PASS, 0 FAIL -- DEMO PASSES
```

Exit codes: **0** means all 29 steps passed; **1** means the checker found a failure; **3** means the demo could
not be set up (for example, a port was already in use), and the checker was not run.

The run's files are left in `demo/run/`:

- `transcript.tsv`: what each master got back;
- `plc-writes.tsv`: the simulated PLC's own log of every write that reached it;
- `events.tsv`: the gateway's log of every request it passed or refused, with the refusal's name;
- `*.err`: each process's status lines.

## What the demo does

1. It loads the site policy, `demo/site-water-works.txt`, a small simulated water works.
2. It starts a simulated PLC on port 1502.
3. It starts the gateway in front of it: port 5020 is the SCADA master, port 5021 is the historian.
4. It plays a 29-step script (`demo/script.txt`) from the master side.
5. It stops every process, then runs the checker (`demo/demo-check.bb`), which is the only verdict.

Each write step is checked twice: against the reply the master received, and against the PLC's own write log. So a
refused write that still reached the PLC would show as a FAIL.

The site policy, in short:

- SCADA may read and write; the historian may only read.
- Spare registers 110 to 119 are not writable.
- The chlorine dosing setpoint (register 100) must stay within 10 to 80 (0.10 to 0.80 mg/L).
- SCADA may make at most 5 writes per 10 seconds.
- For 30 seconds after "pump stop" (coil 0 set to 0), "inlet valve open" (coil 1 set to 1) is refused.

### The 29 steps

| # | Step | Master | Request | Expected | What it shows |
|---:|---|---|---|---|---|
| | **A. Allowed traffic** | | | | |
| 1 | hist-read-flow | historian | read input register 0 | ok, 200 | an allowed read passes |
| 2 | hist-read-setpoint | historian | read register 100 | ok, 50 | |
| 3 | scada-write-setpoint-60 | SCADA | write 60 to register 100 | ok | an in-limit write passes and reaches the PLC |
| 4 | scada-readback-60 | SCADA | read register 100 | ok, 60 | |
| 5 | scada-pump-start | SCADA | set coil 0 to 1 | ok | |
| | **B. Refused by name; nothing reaches the PLC** | | | | |
| 6 | setpoint-95-above-limit | SCADA | write 95 to register 100 | exception 03 | above the limit |
| 7 | setpoint-5-below-limit | SCADA | write 5 to register 100 | exception 03 | below the limit |
| 8 | fc16-multi-out-of-limit | SCADA | write 90, 150, 700 to registers 100 to 102 | exception 03 | one bad value refuses the whole write |
| 9 | write-spare-reg-115 | SCADA | write to register 115 | exception 02 | address not writable |
| 10 | historian-writes-coil-0 | historian | set coil 0 to 0 | exception 01 | function not allowed for this master |
| 11 | fc22-not-allowed-scada | SCADA | mask write (FC 22) | exception 01 | function not allowed |
| 12 | fc8-diagnostics | SCADA | diagnostics (FC 8), raw bytes | exception 01 | function not allowed |
| 13 | fc43-mei-0d-canopen | SCADA | CANopen request (FC 43/13), raw bytes | exception 01 | function not allowed |
| 14 | malformed-protocol-id-1 | SCADA | frame with protocol id 1 | no reply | malformed frame dropped |
| 15 | malformed-length-768 | SCADA | frame claiming length 768 | no reply | impossible length dropped |
| 16 | readback-after-refusals | SCADA | read registers 100 to 102 | ok, 60, 200, 850 | the PLC is unchanged |
| | **C. Forbidden sequence** | | | | |
| 17 | scada-valve-shut | SCADA | set coil 1 to 0 | ok | |
| 18 | scada-pump-stop | SCADA | set coil 0 to 0 | ok | arms the sequence rule |
| 19 | valve-open-after-stop | SCADA | set coil 1 to 1 | exception 04 | refused: within 30 s of pump stop |
| 20 | coils-after-sequence | SCADA | read coils 0 to 2 | ok, 0, 0, 0 | the valve stayed shut |
| | **D. Rate limit** | | | | |
| 21 | pause-rate-window | | wait 10.5 s | | empties the rate window |
| 22 | burst-1 | SCADA | write 21 to register 100 | ok | |
| 23 | burst-2 | SCADA | write 22 | ok | |
| 24 | burst-3 | SCADA | write 23 | ok | |
| 25 | burst-4 | SCADA | write 24 | ok | |
| 26 | burst-5 | SCADA | write 25 | ok | fifth write in 10 s |
| 27 | burst-6-rate-exceeded | SCADA | write 26 | exception 06 | sixth write refused |
| 28 | final-setpoint | historian | read register 100 | ok, 25 | the refused 26 never landed |
| 29 | final-flow-pump-stopped | historian | read input register 0 | ok, 0 | |

A note on step 10's log column: the entry `plc-log HAS [5 0 "0"] x1` is the later, allowed pump stop from step 18.
The historian's own write did not reach the PLC.

Modbus has no standard exception code for "refused by policy". The gateway uses 03 for a value limit, 02 for an
address that is not writable, 01 for a function that is not allowed, 04 for a forbidden sequence and 06 for the rate
limit. The refusal's name is always recorded in `events.tsv`.

## Honest limits

- **This is a loopback simulation.** The PLC is simulated and everything runs on one Raspberry Pi. The package is not
  connected to, and is not ready to be connected to, real equipment.
- **Linux itself is not proven**, nor is babashka, the C library, or the network stack. The proofs cover the 35 cores.
- **The five gateway programs around the cores are tested, not proved.** They handle sockets, timers, process pipes
  and logging. They were tested with their own test suites when they were built, and here by the 29-step demo.
- **Modbus/TCP only.** The RTU framing cores are proved and included, but there is no serial gateway.
- **The demo tells masters apart by port** (5020 and 5021). A real site would use one port (502) and tell masters
  apart by their network address.
- **No authentication or encryption.** Modbus/TCP has neither; the gateway trusts the network's source address.
- **A restart forgets state.** Rate windows and armed sequence rules live in memory.
- **Rate windows are fixed, not sliding.** A burst that straddles a window boundary can pass up to twice the limit.
- **Slow-sender protection** (per-frame and idle time-outs, a cap of 16 masters) is tested, not proved.
- **The release's programs were compiled on a Raspberry Pi with GNAT 15.1.2**, not with the exact compiler build used
  where the gateway was first built (GNAT 15.0.1, which has no aarch64 Linux build). The source is the same, and the
  demo's outputs match that first run byte for byte apart from timings.

`demo/README.md` is the gateway's longer technical note. It lists exactly
which properties are proved and which are tested.

## What is here

| Path | What it is |
|---|---|
| `run-demo` | the one-command launcher (a babashka script) |
| `src/wu-lovelace-mb-<name>/` | the five gateway programs: each program's `.adb` source, the proven core `.ads` files it carries, `edge.gpr`, `carried.tsv` (each carried core with its checksum and ledger number) and `provenance-A.json` (the build record the demo runner reads) |
| `proofs/` | the 35 proven cores, each with `proof.gpr` and the prover's report from a Raspberry Pi; `proofs/README.md` has the table and the re-prove steps |
| `demo/` | the demo runner, checker, 29-step script and site policy |
| `test-equipment/` | the simulated PLC and test controller, and libmodbus (see below) |
| `build/` | the Linux build file, libmodbus `config.h`, and the build steps with Alire |
| `LICENSE`, `NOTICE` | the MIT licence for our code, and the third-party notices |

The release download adds the prebuilt binaries and `bin/bb` (babashka 1.12.196, unmodified, under the Eclipse Public
License 1.0; see `bin/BABASHKA-LICENCE.txt`).

The five gateway programs are `site-loader` (reads the site policy) and the four joined by pipes at run time:
`master-listener | policy-gate | plc-forwarder | master-replier`.

## The simulated PLC and test controller (libmodbus)

`mb_plc_sim` and `mb_demo_master` are test equipment, never part of the gateway. They are built from libmodbus 3.2.0
(commit a9b025d, https://github.com/stephane/libmodbus), **used unmodified** and linked statically. libmodbus is
licensed under the GNU Lesser General Public License, version 2.1 or later; its source and licence are in
`test-equipment/libmodbus/`. The gateway contains no libmodbus code; its cores were specified from the public Modbus
specifications. See `test-equipment/README.md`.

## Licence

Our code is open source (MIT); see `LICENSE`. Third-party components keep their own licences; see `NOTICE`.

## Contact

Anthony Gair, The Dark Factory Ltd
tony.gair@thedarkfactory.co.uk
