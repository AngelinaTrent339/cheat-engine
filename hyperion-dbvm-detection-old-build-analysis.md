# Hyperion DBVM Detection — Old Roblox Build (dump.bin)

This report documents the DBVM-specific detection logic found in the old Roblox build currently loaded in IDA (module `dump.bin`). It focuses on provable evidence: exact addresses, CPUID leaves, and exit behavior that trigger when DBVM is detected.

- Image base: `0x7FFDABAA0000`
- Key entry points: `TlsCallback_0` at `0x7FFDAC62B380`, `DllEntryPoint` at `0x7FFDAC7B0050`

---

## TLS DBVM Gate (0x7FFDAC62B380)

The TLS callback performs several CPUID queries and contains a direct DBVM-kill path conditioned on a folded match against the hypervisor CPUID leaf.

- CPUID leaves issued in TLS (EAX values, ECX=0):
  - `0x0000000D` at `0x7FFDAC62B3A2`
  - `0x80000017` at `0x7FFDAC62B4F3`
  - `0x40000006` at `0x7FFDAC62B7EA`  ← DBVM hypervisor signature leaf
  - `0x00000009` at `0x7FFDAC62B89E`

- DBVM signature predicate (folded compare):
  - `pextrw ecx, xmm0, 4` at `0x7FFDAC62B6B0`
  - `xor eax, ecx` at `0x7FFDAC62B6B5`
  - `cmp ax, 0x25` at `0x7FFDAC62B6B7`
  - If equal, process is terminated with a DBVM-specific status.

- Kill behavior (prove):
  - `mov edx, 0x00BADD00D` at `0x7FFDAC62B70F`
  - `mov rcx, -1` at `0x7FFDAC62B708` (CurrentProcess)
  - `call qword ptr [rip-0x9FF31A]` at `0x7FFDAC62B714` → resolves to imported `NtTerminateProcess`

These instructions occur after issuing `cpuid` with `EAX=0x40000006` and preparing a keyed constant bank loaded into `xmm0` (see `movdqa xmm0, [rsp+...var_128]` at `0x7FFDAC62B656`, where the constant area includes `...0x19A71CBD`) used in the folded comparison. This is a classic “EAX folding + mask + low-word match” against DBVM’s reported hypervisor ID.

- Alternate early exit (prove): when `a2 == 0` (TLS reason 0), the code also calls `NtTerminateProcess(-1, 0)` at `0x7FFDAC62B9B5`, not a crash scaffold.

Conclusion for TLS: this build kills on a DBVM-positive signature based on CPUID leaf `0x40000006` alone; there is no noisy “crash scaffold” or pointer/PEB/TEB sentinel suite in TLS.

---

## Stage-2 Recheck (Dll Initialisation Path)

The module re-enters a stage routine that again interrogates the DBVM leaf and proceeds with obfuscated syscall activity.

- Call path:
  - `DllEntryPoint` at `0x7FFDAC7B0050` → `sub_7FFDAC7AFF28` → `sub_7FFDAC5FF1B0` → `sub_7FFDAC74E770(int stage)`

- At `stage == 2` (prove):
  - `cpuid` with `EAX=0x40000006` at `0x7FFDAC74E7CF`
  - Direct `syscall` sites (no import thunks):
    - `syscall` at `0x7FFDAC74EBBF`
    - `syscall` at `0x7FFDAC74ED74`
  - The routine mixes hashed state from a global array and TEB thread ID to index a table, but it does not import `NtSetInformationProcess` or expose the string “ProcessInstrumentationCallback” in this build. The syscalls are performed via obfuscated indices.

Conclusion for stage 2: the old build re-uses the DBVM CPUID leaf during initialisation and executes direct syscalls through obfuscated tables. No user-visible WER-style crash scaffolds or loader/PEB sentinels are present.

---

## Imports and Absent Indicators (Evidence)

- Present:
  - `NtTerminateProcess` imported from `ntdll` (used by TLS to kill): import address table includes `NtTerminateProcess` at `0x7FFDABC2C400`.

- Absent (prove by import/string scan):
  - No `NtSetInformationProcess` import.
  - No string for “ProcessInstrumentationCallback”.
  - No WER/“Third‑party interference” strings.

This supports that the old build’s DBVM handling is a direct, early kill triggered by hypervisor CPUID leaf inspection, not by later-stage crash scaffolds.

---

## Why Changing DBVM Passwords Worked (Old Build)

DBVM historically encodes its hypervisor CPUID signature (leaf `0x40000006`) using internal constants, including default password values (e.g., `0x76543210` and companions). In this old build:

- TLS folds the leaf’s `EAX` using a keyed constant bank (the block that includes `...0x1CBD`) and compares the low word to `0x25` before calling `NtTerminateProcess(-1, 0x00BADD00D)`.
- Changing DBVM’s default passwords alters the low-word of the hypervisor signature reported in `EAX` for `0x40000006`; the folded predicate no longer equals `0x25`, so the TLS gate does not kill → making the build UD, as observed.

This is consistent with the absence of any additional pointer/loader/TEB sentinels or crash scaffolds in this build: the detection hinges on the hypervisor leaf alone.

---

## Address Index (for IDA cross-check)

- TLS callback entry: `0x7FFDAC62B380`
- TLS CPUID leaves:
  - `0x0000000D` at `0x7FFDAC62B3A2`
  - `0x80000017` at `0x7FFDAC62B4F3`
  - `0x40000006` at `0x7FFDAC62B7EA`
  - `0x00000009` at `0x7FFDAC62B89E`
- TLS folded match and kill:
  - Fold: `0x7FFDAC62B6B0` → `0x7FFDAC62B6BB`
  - Kill: `NtTerminateProcess(-1, 0x00BADD00D)` at `0x7FFDAC62B714`
  - Early zero-exit: `NtTerminateProcess(-1, 0)` at `0x7FFDAC62B9B5`
- Stage path:
  - `DllEntryPoint`: `0x7FFDAC7B0050`
  - `sub_7FFDAC7AFF28` dispatcher
  - `sub_7FFDAC5FF1B0` → `sub_7FFDAC74E770`
  - Stage-2 DBVM leaf CPUID: `0x7FFDAC74E7CF` (EAX=`0x40000006`)
  - Direct syscalls: `0x7FFDAC74EBBF`, `0x7FFDAC74ED74`

---

## Bottom Line

- Old build: DBVM detection is anchored in CPUID leaf `0x40000006` in TLS (hard kill with `0x00BADD00D`) and re-checked during stage 2 via direct syscalls. No pointer/PEB/TEB sentinels or intentional crash scaffolds were identified.
- This explains why changing DBVM defaults (passwords) changed the hypervisor signature and made this build UD.
- The newer build (separate report) adds more layers (loader/PEB sentinels, hybrid-topology consistency, crash scaffold), which will be compared side-by-side once plugged.

