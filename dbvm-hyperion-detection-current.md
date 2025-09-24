# DBVM Detection Status – Hyperion/Byfron Probe

This note correlates the Hyperion detector observed in `dump.bin` with the DBVM sources in this repository. It separates *runtime observations* (what the anti-cheat is doing) from *repository behaviour* (what this tree actually returns) so we can see exactly where the discrepancies lie.

## 1. Hyperion Probe (runtime evidence)
- Function `sub_7FF93428D910` builds `{ out=&v5, in=&0xFEDCBA98_0000000C }`, calls the shim `sub_7FF93428DD70`, then executes:
  - `C1 E0 18` ? `shl eax, 0x18`
  - `3D 00 00 00 CE` ? `cmp eax, 0xCE000000`
  - `0F 85 …` ? branch into `sub_7FF934371A80(0x13,3,2,0,0)` on equality.
- The shim at `0x7FF93428DD70` loads `EDX=0x76543210` and `ECX=0x90909090`, executes `vmmcall`, and stores the returned `RAX` into `*out`. `0x7FF93428DE00` is the Intel copy using `vmcall`.
- There is no post-processing between the shim and the compare—the call to `sub_7FF93422B8A0` decompiles to a no-op stub—so whatever value the hypervisor wrote is what gets compared.
- In the captured run, `BYTE3(RAX_from_vmcall)` equals `0xCE`, so the kill path fires despite password randomisation.

## 2. DBVM Repository Behaviour (source evidence)
### 2.1 Call IDs
- `dbvm/vmm/vmcall.h` defines the small ordinal IDs: `VMCALL_GETVERSION 0`, `VMCALL_CHANGEPASSWORD 1`, `VMCALL_CHANGESELECTORS 12`, etc. The Pascal wrapper `Cheat Engine/dbk32/vmxfunctions.pas` uses the same constants. This tree does **not** map GETVERSION to 183 or CHANGESELECTORS to 203.

### 2.2 Password Gate
- `handleVMCall` (Intel path in `dbvm/vmm/vmeventhandler.c:4401-4410`, AMD path in `dbvm/vmm/vmeventhandler_amd.c:1379-1385`) hands control to `dbvm/vmm/vmcall.c`.
- The first logic in `handleVMCall` (lines 2413-2442) maps the instruction payload and checks `RDX`/`RCX` against `Password1/Password3`. On mismatch it raises `raiseGeneralProtectionFault(0)` and **never** enters the switch.

### 2.3 GETVERSION return format
- Case `VMCALL_GETVERSION` (lines 944-960) returns `(Password1 ^ Password3) & 0xFF000000ULL + dbvmversion`. With the obfuscated passwords from `dbvm/vmm/main.c:298-317`, that upper byte resolves to `0xD9`, not `0xCE` or `0xA7`.

### 2.4 CHANGESELECTORS (ID 12)
- Case 12 (`dbvm/vmm/vmcall.c:1153-1172`) calls `change_selectors(...)` on Intel and returns `0xDADEAD` immediately on AMD (`if (isAMD) { vmregisters->rax = 0xDADEAD; break; }`). None of these values carry a `0xCE` in byte 3.

### 2.5 No top-byte tagging
- A repo-wide search finds no code that ORs/sets `0xCE000000` in the common return path. Each vmcall case fills `vmregisters->rax` independently; there is no global tag injection.

**Conclusion for the repo:** if you build this tree as-is, a vmcall issued with wrong passwords raises #GP; a successful GETVERSION returns `0xD9xxxx13`; CHANGESELECTORS returns `0x00000000` (success) or `0x00DADEAD` (failure). None of those satisfy `BYTE3 == 0xCE`.

## 3. Reconciling Repo vs Runtime
Because the anti-cheat sees `BYTE3 == 0xCE`, one of the following must be true in the environment you reversed (but not in this repo snapshot):
1. **Private changes / runtime patching.** Your DBVM build may tag return codes (e.g., `RAX = 0xCE000000 | status`). Those edits are not present in this tree, so the repo doesn’t show them.
2. **Different handler executed.** The input block `0xFEDCBA98_0000000C` could route to a handler that isn’t `VMCALL_CHANGESELECTORS` (for example, an extended ABI where the low dword encodes more than an ID). If that handler returns a value with top byte `0xCE`, the probe still trips.
3. **Call succeeds before password guard.** If your runtime places the password check in a different spot (or leaves default credentials somewhere reachable), the handler runs and returns whatever status code carries the `0xCE` mark.

To determine which of these is happening, you need runtime instrumentation:
- **Breakpoint the shim write** (`mov [r8], rax`) in `sub_7FF93428DD70` and record `RAX` with DBVM absent/present, and with valid/invalid passwords. This tells you exactly what value is being returned pre-compare.
- **Temporarily patch the handler** in your build (e.g., return `0xAA00000C` for Call ID 12) and re-run the probe. If the compare still hits on `0xCE`, you know you aren’t hitting that handler.
- **Log the password gate** (e.g., add a serial print or Bochs `out` when the guard rejects a call) to see whether the probe reaches `_handleVMCallInstruction` at all.

## 4. Mitigation Strategies
Regardless of the exact source of the `0xCE` byte, the following harden this probe:
1. **Fault before returning.** Move the password check to the VM-exit handlers (`vmeventhandler.c` / `vmeventhandler_amd.c`) so invalid requests raise #GP/#UD before any handler writes to guest memory.
2. **Remove the tag.** Ensure any handler that runs returns codes without a stable top byte. If you rely on a tag internally, randomise or mask it before writing to the guest.
3. **Audit other probes.** Search the detector for the same shim signature (`mov ecx, 90909090 / mov edx, 76543210 / vmcall`) and inspect what it does with the return. Patch or defend accordingly.

## 5. Next Validation Steps
1. Instrument `_handleVMCallInstruction` in your dev build to log each Call ID and return value. That gives you ground truth for the running binary.
2. Re-run Hyperion’s probe with logging enabled; capture both the pre-compare buffer and DBVM’s handler output.
3. Update this document with the observed values so we can pinpoint where `0xCE` is introduced.
4. After implementing mitigations, repeat the probe to confirm `BYTE3` no longer equals `0xCE` (or the call faults).

By keeping the runtime evidence and repository code paths separate, we can reason about what needs to change in *your* build to defeat this specific check.