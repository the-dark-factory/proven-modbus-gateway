# Proof summary: the 35 proven gateway cores

Every decision the gateway makes is taken by one of these 35 SPARK Ada packages. Each one was proved with
GNATprove, and the proof was checked again on a Raspberry Pi 4 (Debian 12, aarch64) on 2026-10-14.

| | |
|---|---|
| Cores | 35 |
| Checks (verification conditions) in total | 2,378 |
| Unproved | 0 |
| Prover | gnatprove 15.1.0 (reports itself as "FSF 15.0"), Why3 1.7.1, provers CVC5, Z3 and Alt-Ergo |
| Command, per core | `gnatprove -P proof.gpr --level=2 --report=all -j4` |
| Result | identical totals on the Raspberry Pi and on the macOS machine the cores were first proved on |

Each folder below holds:

- the core's `.ads` (a SPARK package; the code and its contracts are in the specification itself);
- the `.ads` of the other cores it depends on;
- `proof.gpr`, the project file the proof is run with;
- `gnatprove.out.pi`, the prover's own report from the Raspberry Pi run.

"Checks" means every obligation GNATprove generated for the core: absence of run-time errors (no overflow, no index
out of range, no division by zero), the data-flow checks, and every pre- and postcondition the core states.
The "Ledger" column is the core's admission number in The Dark Factory's proof ledger.

| Core folder | Package | Checks | Unproved | Ledger |
|---|---|---:|---:|---:|
| addr-span | Lovelace_Mb_Addr_Span_Pkg | 5 | 0 | 624 |
| allow-fc | Lovelace_Mb_Allow_Fc_Pkg | 43 | 0 | 634 |
| bounds | Lovelace_Mb_Bounds_Pkg | 11 | 0 | 610 |
| crc16-step | Lovelace_Mb_Crc_Step_Pkg | 18 | 0 | 615 |
| crc16-wire | Lovelace_Mb_Crc_Wire_Pkg | 14 | 0 | 616 |
| fc-catalog | Lovelace_Mb_Fc_Catalog_Pkg | 17 | 0 | 625 |
| frame-refusals | Lovelace_Mb_Frame_Refusal_Pkg | 5 | 0 | 614 |
| gate-decide | Lovelace_Mb_Gate_Decide_Pkg | 441 | 0 | 680 |
| gate-next | Lovelace_Mb_Gate_Next_Pkg | 345 | 0 | 682 |
| gate-refusals | Lovelace_Mb_Gate_Refusal_Pkg | 6 | 0 | 620 |
| mbap-fields | Lovelace_Mb_Mbap_Pkg | 18 | 0 | 617 |
| pdu-dispatch | Lovelace_Mb_Pdu_Dispatch_Pkg | 150 | 0 | 643 |
| pdu-fields | Lovelace_Mb_Pdu_Fields_Pkg | 20 | 0 | 623 |
| pdu-refusals | Lovelace_Mb_Pdu_Refusal_Pkg | 4 | 0 | 622 |
| pdu-view | Lovelace_Mb_Pdu_View_Pkg | 214 | 0 | 672 |
| policy-shape | Lovelace_Mb_Policy_Shape_Pkg | 41 | 0 | 633 |
| proxy-match | Lovelace_Mb_Proxy_Match_Pkg | 51 | 0 | 621 |
| rate-window | Lovelace_Mb_Rate_Window_Pkg | 52 | 0 | 637 |
| req-device-id | Lovelace_Mb_Req_Device_Id_Pkg | 26 | 0 | 642 |
| req-mask-write | Lovelace_Mb_Req_Mask_Write_Pkg | 34 | 0 | 628 |
| req-read-bits | Lovelace_Mb_Req_Read_Bits_Pkg | 32 | 0 | 626 |
| req-read-words | Lovelace_Mb_Req_Read_Words_Pkg | 32 | 0 | 627 |
| req-read-write | Lovelace_Mb_Req_Read_Write_Pkg | 34 | 0 | 641 |
| req-write-coils | Lovelace_Mb_Req_Write_Coils_Pkg | 37 | 0 | 639 |
| req-write-registers | Lovelace_Mb_Req_Write_Registers_Pkg | 34 | 0 | 640 |
| req-write-single | Lovelace_Mb_Req_Write_Single_Pkg | 44 | 0 | 629 |
| resp-echo-shape | Lovelace_Mb_Resp_Echo_Pkg | 45 | 0 | 632 |
| resp-exception | Lovelace_Mb_Resp_Exception_Pkg | 32 | 0 | 630 |
| resp-read-shape | Lovelace_Mb_Resp_Read_Pkg | 57 | 0 | 631 |
| rtu-adu-accept | Lovelace_Mb_Rtu_Accept_Pkg | 28 | 0 | 618 |
| sequence-guard | Lovelace_Mb_Sequence_Pkg | 73 | 0 | 638 |
| tcp-adu-length | Lovelace_Mb_Tcp_Adu_Pkg | 27 | 0 | 619 |
| value-limit | Lovelace_Mb_Value_Limit_Pkg | 76 | 0 | 636 |
| write-effects | Lovelace_Mb_Write_Effect_Pkg | 260 | 0 | 678 |
| write-range | Lovelace_Mb_Write_Range_Pkg | 52 | 0 | 635 |
| **Total** | | **2,378** | **0** | |

The three RTU cores (crc16-step, crc16-wire, rtu-adu-accept) are proved but not used by this TCP-only gateway.

The `.ads` files here are byte-identical to the files the factory proved and admitted. The copies carried in
`../src/` are the same files; `../src/*/carried.tsv` lists each one with its checksum and ledger number.

## Re-prove it yourself

You need Alire (`alr`), the Ada package manager, version 2.1.1 or later (https://alire.ada.dev). On Debian 12,
alr 2.1.0's aarch64 build needs a newer glibc than bookworm has; 2.1.1 works. Downloading the prover takes a few
minutes. These commands work on Linux and macOS.

```
alr settings --global --set cache.dir $HOME/alire-cache
cd $HOME
alr get gnatprove=15.1.0
export PATH=$(echo $HOME/gnatprove_15.1.0_*/bin):$PATH
gnatprove --version          # expect: FSF 15.0

cd <this folder>/gate-decide
gnatprove -P proof.gpr --level=2 --report=all -j4
grep '^Total' obj/gnatprove/gnatprove.out
grep '^Total' gnatprove.out.pi
```

The last two lines should match: for gate-decide, 441 checks, all proved, 0 unproved. Repeat in any other folder.
To prove all 35 in one go:

```
for d in */; do (cd "$d" && gnatprove -P proof.gpr --level=2 --report=all -j4 --quiet && grep '^Total' obj/gnatprove/gnatprove.out); done
```

On a Raspberry Pi 4 the whole set takes about 50 minutes; gate-decide alone takes about 12 minutes. A faster machine
takes a fraction of that. The prover's choices can vary slightly between machines (which prover closes which check),
but the number of checks and "0 unproved" should not.

If alr cannot fetch its index because your git configuration rewrites GitHub https addresses to ssh, you can run the
alr command with an empty git configuration: `GIT_CONFIG_GLOBAL=/dev/null alr get gnatprove=15.1.0`.
