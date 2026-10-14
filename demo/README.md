# Modbus/TCP water-gateway demo

This page is for a water or energy utility, or for an integrator who works for one. It explains what the gateway does,
how to run the demo with one command, what the demo shows, and which properties are **proved** and which are only
**tested**.

## What the gateway does

The gateway sits between your SCADA or historian masters and a PLC, on Modbus/TCP. It checks every request against a
**site policy** that you declare, and it acts on the result:

- If the request passes, the gateway forwards it to the PLC unchanged and relays the reply.
- If it is refused, nothing reaches the PLC. The master gets a standard Modbus exception, and the gateway logs the
  refusal by name.

The policy is a short text file. The demo's policy is [`site-water-works.txt`](site-water-works.txt). Per master it
declares:

- **Which function codes it may use.** In the demo, SCADA may read and write; the historian may only read.
- **Which coils and registers it may write.** Spare registers 110..119 are not writable.
- **Value limits per register.** The chlorine dosing setpoint (register 100) must stay within 10..80, which is
  0.10..0.80 mg/L.
- **A rate limit.** SCADA may make at most 5 writes per 10 s.
- **Forbidden sequences.** For 30 s after "pump stop" (coil 0 := 0), "inlet valve open" (coil 1 := 1) is refused.

Masters are told apart by their source address and the gateway port they connect to. In the demo both run on one
host, so the two masters use two ports: 5020 is SCADA and 5021 is the historian. A real site would use one port (502)
and distinct master addresses.

| refusal | exception the master sees |
|---|---|
| function not allowed for this master, or unknown function | 01 |
| address not writable | 02 |
| value below or above the register's limit | 03 |
| forbidden sequence | 04 |
| rate exceeded | 06 |
| malformed frame (bad protocol id, impossible length) | no reply; the connection is closed |
| PLC silent, unreachable, or gave a malformed reply | 0B, 0A, or 04 |

Exception 03 normally means "illegal data value". No standard code means "refused by policy", so the gateway uses 03
for a limit refusal, 06 for the rate limit and 04 for a sequence. The authoritative record is the
refusal **name** in the gateway's event log.

The gateway runs as four small programs joined by pipes:
`master-listener | policy-gate | plc-forwarder | master-replier`.

- **master-listener** accepts the masters and reads exactly one frame at a time.
- **policy-gate** decides PASS or REFUSE(name), and holds the rate and sequence state.
- **plc-forwarder** decides the request again on a fresh state before any byte reaches the PLC, then talks to the
  PLC.
- **master-replier** answers the master and writes the event log.

Every decision is made by a **proved core**. The four programs only do sockets, timers and formatting.

## The one command

On a Raspberry Pi, from the unpacked release folder, run `./run-demo` (see `../README.md`). From a source tree with
babashka installed, the equivalent is `MB_FACTORY=$PWD/src bb demo/run-demo.bb` (see `../build/README.md`).

The run takes about 14 s and uses the loopback ports 1502, 5020, 5021 and 5029. The command:

1. Uses the five gateway programs in `../src/`. If a binary is missing or older than its source, it rebuilds it
   with gprbuild.
2. Loads the site policy.
3. Starts the simulated PLC on port 1502. This is libmodbus, linked unmodified, and it enforces nothing itself.
4. Starts the gateway.
5. Plays a 29-step script from the master side ([`script.txt`](script.txt)).
6. Stops every process. It does this even when something fails.
7. Runs the checker, [`demo-check.bb`](demo-check.bb), which is the only verdict.

**Exit code:**

- 0 means the checker passed every step.
- 1 means the checker found a failure.
- 3 means the demo could not be set up, for example because a port was taken. The checker is not run in that case.

The files from the last run are in `demo/run/`:

- `transcript.tsv`: what each master got back.
- `plc-writes.tsv`: the PLC's own log of every write that reached it.
- `events.tsv`: the gateway's refusal and relay log.
- `*.err`: each process's status lines.

To build the two fixtures (the PLC and the master) from source, see `../build/README.md`. Run with no gateway
(the master talking straight to the PLC), the same script shows the bare PLC obeying every dangerous write.

## What you will see

There is one line per script step, then a summary. Each write step is checked twice:

- against what the master received;
- against the PLC's own write log, so a refused write that still reached the PLC shows as a FAIL.

The steps fall into four groups:

- **A. Allowed traffic:** historian reads, a SCADA setpoint write of 60, a readback and a pump start. All pass, and
  every write is in the PLC log.
- **B. Refused by name:**
  - setpoint 95 and 5 (03);
  - a three-value write with one value out of limit (03);
  - a write to spare register 115 (02);
  - the historian writing a coil (01);
  - mask-write, diagnostics and a CANopen request (01);
  - two malformed frames (no reply).

  None of these writes reaches the PLC. The readback afterwards still shows 60, 200, 850.
- **C. Forbidden sequence:** valve shut, pump stop, then "valve open" is refused 04. The coils read back 0, 0, 0.
- **D. Rate:** a 10.5 s pause, then six setpoint writes in a row. Five pass and the sixth is refused 06. The final
  setpoint reads 25.

The run ends with `SUMMARY: 29 checks, 29 PASS, 0 FAIL -- DEMO PASSES`.

A note on reading the log column: in the line for `historian-writes-coil-0`, the entry "plc-log HAS [5 0 "0"] x1" is
the **later**, allowed SCADA pump stop from section C. The checker counts each write key as a multiset (expected 1,
found 1). The historian's write did not reach the PLC.

## PROVED vs TESTED

**PROVED** means the property holds for every input. It was discharged by GNATprove (SPARK) on the core and admitted
to the factory ledger. The ledger ids are in brackets.

- **The product theorem.** If the gate passes a register write, every value written lies within every declared limit
  of the register it lands on (`Min <= value <= Max`). This is the postcondition of gate-decide [680]. It is stated
  over the raw request bytes, with no helper function in its premise. It covers single, multiple and read-write
  register writes. It is built on value-limit [636] and write-effects [678].
- **Refusal properties of the same decision [680]:**
  - A PASS also means the function is allowed for that master [634], every written address is writable [635], the
    rate is within its window [637], and no forbidden sequence is hit [638].
  - A mask-write (FC22) can pass only on a register that has no limit and no sequence rule.
  - Allowed reads pass, and a full write window never refuses a read.
  - Completeness: a write that meets every rule passes.
  - A value refusal is named "below" exactly when some value is below its limit.
- **State update.** gate-next [682] proves that refusals and reads never change the rate or sequence state.
- **Policy shape and refusal codes:** policy-shape [633], gate-refusals [620].
- **Framing.** These cores are proved to have no runtime errors, to respect the spec's size bounds, and to be
  length-consistent: bounds [610], frame-refusals [614], mbap-fields [617], tcp-adu-length [619]; for RTU, CRC-16
  [615, 616] and the CRC-gated accept [618]. No frame is read past 260 bytes.
- **Request parsing for FC 1-6, 15, 16, 22, 23 and 43/14.** Every count and byte count is checked before any field is
  read, and illegal combinations are refused by name: pdu-refusals [622], pdu-fields [623], addr-span [624], fc-catalog
  [625], the request cores [626-629, 639-642], pdu-dispatch [643] and pdu-view [672].
- **Replies and matching:** resp-exception [630], resp-read-shape [631], resp-echo-shape [632], proxy-match [621].

**TESTED** means the property was checked on finite cases and is not proved.

- **The four gateway programs and site-loader.** These "edges" are built, not proved. Each one was verified when it
  was built, by its own test suite ("probe"):
  - listener 24/24;
  - policy-gate 12/12, including a 3,000-request stateful stream that matches a reference model line for line;
  - forwarder 34/34;
  - replier 32/32;
  - site-loader 42/42.

  For each probe, deliberately broken stand-ins were built and every one failed it.
- **The gateway as a whole.** That a refused request never reaches the PLC is tested, by this 29-step demo and the
  probes. The cores make the decision; the wiring around them is tested.
- **Agreement with libmodbus v3.2.0 (pinned a9b025d).** libmodbus was used as an independent oracle. All 6,505
  server-side request cases were compared: 4,770 agree, and 1,735 diverge. Every divergence belongs to one of the named
  classes O1-O11, and each class is explained; 0 are unexplained. All 706 TCP reply cases were also checked. The
  cores are specified from the public Modbus specifications (APP V1.1b3, TCP V1.0b), not from libmodbus.
- **Slow senders.** These are the CVE-2026-51539 kind of attack. The gateway applies these bounds:
  - 1 s per frame;
  - 1 s per PLC reply;
  - at most 16 masters at once;
  - a 60 s idle limit;
  - a 5 s reply wait.

  They are tested with slow-sender stand-ins and are **not proved**. The proofs cover byte verdicts only.

## Limits (stated plainly)

- **A restart forgets state.** Rate windows and armed sequence triggers live in the policy-gate process. Restarting
  the gateway reopens every window and forgets every trigger.
- **Rate windows are fixed, not sliding.** A burst that straddles a window boundary can pass up to 2 x the limit.
- **A sequence trigger lapses after its window.** It is not disarmed by a later write. A single request that performs
  both steps of a forbidden sequence is refused.
- **Trailing reply bytes.** The current setting is that a PLC reply with extra bytes after the
  length its header declares is treated as malformed. The master gets exception 04, and the reply is not relayed. The
  alternative, relaying the declared bytes and discarding the rest, is a one-line change that awaits a ruling.
- **Modbus/TCP only.** The RTU framing cores are proved, but there is no serial gateway.
- **The unit id must be echoed.** A PLC that answers with a fixed unit id 0xFF instead of echoing the request's unit
  id would have every reply refused 04.
- **The demo runs on one host, using ports for identity.** A real deployment identifies masters by address on port 502.
- **No authentication or encryption.** Modbus/TCP has neither, so the gateway trusts the network's source address.
- **The forwarder's second check is stateless.** It re-checks function, address and value limits. The rate and
  sequence rules are enforced only by the policy-gate.

## Where the evidence is

- `../proofs/`: every proven core, its proof project and the prover's report; `../proofs/README.md` has the table
  and the steps to re-prove.
- `../src/*/carried.tsv`: which proven cores each gateway program carries, with their checksums and ledger numbers.
