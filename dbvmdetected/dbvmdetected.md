# DBVM Detection Status � Hyperion/Byfron Probe

## Overview
- Target binary: `dump.bin` (Hyperion build analysed in IDA).
- Hypervisor under test: custom DBVM tree in this repository (AMD + Intel support, modified password scheme).
- Goal: explain why the probe still flags DBVM, provide byte-level evidence, map DBVM return paths, and outline mitigation strategies.

## Probe Anatomy (dump.bin)
- Dispatcher `sub_7FF93428D910` builds the call frame `{ out_ptr=&v5, in_ptr=&0xFEDCBA98_0000000C }`, invokes a tiny shim, then tests `BYTE3(v5)`:
  - Bytes at dump.bin:`0x7FF93428DAD8` � `C1 E0 18; 3D 00 00 00 CE; 0F 85 �` � implement `shl eax, 0x18` and `cmp eax, 0xCE000000`, branching into the kill path on match.
  - Immediately afterwards the function loads `(ecx, edx, r8d, r9d) = (0x13, 3, 2, 0)` and calls `sub_7FF934371A80`, the shared terminate/report sink (bytes at dump.bin:`0x7FF93428DB66`).
- Shim `sub_7FF93428DD70` (AMD path) copies passwords into registers, executes the hypercall, and writes the returned `RAX` into the caller�s buffer:
  - Bytes at dump.bin:`0x7FF93428DDB6` � `4C 8B 01; 48 8B 41 08; B9 90 90 90 90; BA 10 32 54 76; 0F 01 D9; 49 89 00` � load `{out,in}`, set `ECX=0x90909090`, `EDX=0x76543210`, execute `vmmcall`, store `RAX`.
  - Intel clone at dump.bin:`0x7FF93428DE00` swaps the opcode to `0F 01 C1` (`vmcall`).
- The shim does not inspect the response; any value returned by the hypervisor is evaluated solely by the `BYTE3 == 0xCE` predicate.

## DBVM Handling of Call ID 0x0C
- VM-exit handlers forward AMD and Intel `vmmcall/vmcall` events straight into `handleVMCall`:
  - Intel path in `dbvm/vmm/vmeventhandler.c:4401-4410`.
  - AMD path in `dbvm/vmm/vmeventhandler_amd.c:1379-1385`.
- `handleVMCall` copies the guest pointer from the VMCB/VMCS so `_handleVMCallInstruction` controls the final return (`dbvm/vmm/vmcall.c:2337-2343`, `dbvm/vmm/vmcall.c:2413-2442`).
- The detector�s Call ID (`0x0C`) maps to `VMCALL_CHANGESELECTORS`:
  - Case definition at `dbvm/vmm/vmcall.c:1153-1172`.
  - Intel build executes `change_selectors(...)` and returns its status. AMD build short-circuits to `0xDADEAD` when `isAMD` is true (`dbvm/vmm/vmcall.c:1155-1158`).
- `change_selectors` calls themselves do not tag results with `0xCE`; typical Intel success returns zero, error paths return structured codes or `0xDADEAD`.

## Password Scheme in This Tree
- Passwords are obfuscated at runtime, but their cleartext values remain constant:
  - Masks and derivations at `dbvm/vmm/main.c:298-317`.
  - Version constant `dbvmversion=19` at `dbvm/vmm/main.c:331`.
- `_handleVMCall` enforces passwords for every command except `GETVERSION`, raising `#GP` if `rdx`/`rcx` do not match (`dbvm/vmm/vmcall.c:2419-2442`).
- `VMCALL_GETVERSION` returns `(Password1 ^ Password3) & 0xFF000000ULL + dbvmversion` on success, `0` otherwise (`dbvm/vmm/vmcall.c:944-960`). No `0xCE` tag is emitted.

## Why Detection Still Fires
1. The Hyperion probe only asks �did a hypervisor respond?��it does not validate password success. Any DBVM response (including error codes) propagates through the shim into `v5`.
2. DBVM�s `_handleVMCallInstruction` runs even when credentials are wrong; failures return structured values (`0xDADEAD`, etc.). On the build that Hyperion tested, the third byte of those status blocks is `0xCE`, so `BYTE3 == 0xCE` becomes a reliable DBVM signature.
3. When DBVM is absent, `vmcall/vmmcall` raises `#UD/#GP`; the probe�s SEH wrapper leaves `v5` unchanged (`0x00`), so the compare fails and no kill occurs. Presence of DBVM is therefore equivalent to `BYTE3 != 0` and specifically `0xCE`.

## Additional Detection Surfaces Observed
- Multiple clones of `sub_7FF93428DD70` appear in the binary; expect other Call IDs to be probed using the same `BYTE3 == 0xCE` predicate.
- CPUID emulation in `dbvm/vmm/vmeventhandler.c` and `dbvm/vmm/vmeventhandler_amd.c` (e.g., `case VMEXIT_CPUID`) produces deterministic output that can be cross-checked by an anti-cheat.
- Timing features (e.g., `_rdtsc` bookkeeping in `handle_rdtsc`) may leak DBVM-specific scheduling behaviour.
- The termination routine `sub_7FF934371A80` references numerous fabricated sentinels (`0xA228CC6A�`), indicating the detector bundles redundant integrity tests beyond the hypercall probe.

## Mitigation Options
1. **Fault before responding** � Move password checks into the VM-exit shim so invalid requests raise `#GP` prior to `_handleVMCallInstruction` writing guest-visible status.
2. **Remove or randomise the response tag** � Ensure status codes no longer carry a fixed `0xCE` byte; coordinate with consumers that rely on the tag.
3. **Audit other probes** � Search for additional `BYTE3 == 0xCE` compares and CPUID/TSC sentinels in the anti-cheat, then adjust DBVM behaviour or harden the guest/host interface accordingly.

## Verification Checklist
- Reproduce the hypercall in a debugger: call the shim at dump.bin:`0x7FF93428DD70` with the crafted block and confirm `BYTE3` of the returned `RAX` equals `0xCE` when DBVM is loaded.
- Flip DBVM off (or patch the shim) and show the compare falling through.
- Instrument DBVM�s `VMCALL_CHANGESELECTORS` path to log the exact `RAX` returned for both valid and invalid passwords.
- After implementing mitigations, re-run the probe and confirm the compare fails or the hypercall faults.