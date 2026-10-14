# Building from source (Raspberry Pi, 64-bit Linux)

These are the steps used to build the release download on a Raspberry Pi 4 running Debian 12 (bookworm, aarch64).
No sudo is needed; everything goes in your home directory. Paths below are relative to the top of this repository.

| File here | What it is |
|---|---|
| `Makefile.linux` | builds the two test-equipment programs (`mb_plc_sim`, `mb_demo_master`) and the libmodbus objects they link |
| `config.h` | a hand-written Linux `config.h` for libmodbus, used instead of its autotools build |

## 1. The Ada toolchain, from Alire

You need Alire (`alr`) 2.1.1 or later (https://alire.ada.dev). On Debian 12, alr 2.1.0's aarch64 build needs a
newer glibc than bookworm has; 2.1.1 works.

```
alr settings --global --set cache.dir $HOME/alire-cache
alr toolchain --select gnat_native=15.1.2 gprbuild=26.0.1
export PATH=$(echo $HOME/alire-cache/toolchains/gnat_native_15.1.2_*/bin):$(echo $HOME/alire-cache/toolchains/gprbuild_26.0.1_*/bin):$PATH
gnat --version               # expect: GNAT 15.1.0 (Alire's gnat_native 15.1.2 build)
```

If alr cannot fetch its index because your git configuration rewrites GitHub https addresses to ssh, you can run
each alr command with an empty git configuration: `GIT_CONFIG_GLOBAL=/dev/null alr ...`.

To re-run the proofs as well, see `../proofs/README.md`.

## 2. The five gateway programs

```
for d in src/wu-lovelace-mb-*/; do (cd "$d" && gprbuild -P edge.gpr -p -q); done
```

Each folder's `edge.gpr` names its one main program and the compiler switches (`-gnat2022 -gnatU -O2`). The
binaries are written next to their source, for example `src/wu-lovelace-mb-policy-gate/mb_policy_gate_main`.
They link only the system C library; the GNAT run-time is linked statically.

## 3. The test equipment (libmodbus-based; needs gcc and make)

```
make -C test-equipment -f ../build/Makefile.linux MB=$PWD/test-equipment/libmodbus OBLD=$PWD/build
```

This writes `test-equipment/mb_plc_sim` and `test-equipment/mb_demo_master`, and the libmodbus objects into
`build/`. libmodbus is compiled from `test-equipment/libmodbus/src/`, unmodified.

## 4. Run the demo from the source tree

`demo/run-demo.bb` expects the two test programs beside it in `demo/`. The release links them there:

```
ln -sf ../test-equipment/mb_plc_sim demo/mb_plc_sim
ln -sf ../test-equipment/mb_demo_master demo/mb_demo_master
MB_FACTORY=$PWD/src bb demo/run-demo.bb
```

You need babashka (`bb`) on your PATH for this; https://github.com/babashka/babashka.

## 5. The release download

The release tarball is this repository's tree plus:

- the binaries from steps 2 and 3, and the two links from step 4;
- `bin/bb`, babashka 1.12.196 (static aarch64 Linux build, unmodified), with its licence notice beside it (`bin/BABASHKA-LICENCE.txt`).

With those in place, `./run-demo` at the top of the tree runs the demo with no other software.
