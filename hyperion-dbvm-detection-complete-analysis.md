# Hyperion DBVM Detection Technical Report (`dump.bin`)

This document records every observable behaviour in the Roblox Hyperion user-mode detector contained in the sample `dump.bin` (image base `0x7FF933640000`). All information below is derived from live analysis with IDA MCP on this build; nothing is inferred from other sources. Addresses are expressed as absolute VA values inside `dump.bin` so they can be looked up directly in the IDA database.

---

## Module Metadata
- Image base: `0x7FF933640000`
- Detected TLS callback: `TlsCallback_0` at `0x7FF93430FAB0`
- Stage orchestrator: `sub_7FF93439A498`
- Deep hardware audit routine: `sub_7FF9343762F0`
- Extended TLS helper: `sub_7FF9343105F0`
- Crash scaffolds: code region spanning `0x7FF9343103B3` – `0x7FF9343105E0` and duplicate blocks inside `sub_7FF9343762F0`
- Global state block frequently accessed: `stru_7FF933870C20` (array of 8-byte slots used for runtime fingerprints, API pointers, and counters)
- Global FLS index storage: `dword_7FF933870240`

---

## Execution Timeline From Process Launch
1. The loader invokes `TlsCallback_0` (`0x7FF93430FAB0`) before C runtime initialisation. All early detection and environment poisoning checks occur here.
2. The CRT enters `sub_7FF93439A498` multiple times with stage arguments 0–3. Each call either replays the TLS logic or performs setup/teardown tasks that support later checks.
3. During stage 2, `sub_7FF93439A498` dispatches to `sub_7FF9343762F0`, which performs the hybrid-topology CPUID verification, loader fingerprint checks, and the Process Instrumentation Callback registration.
4. If every probe succeeds, control returns to CRT initialisation. If any probe fails, control is transferred to the crash scaffolds, resulting in an intentional access violation and a Windows Error Reporting dialog complaining about “Third-party software interfering with Roblox.”

---

## TLS Callback (`0x7FF93430FAB0`)

### 1. Pointer and Stack Sentinels
The callback reads specific fields from the TEB and PEB, masks them, and compares them to precomputed poison constants. Any match immediately jumps into the crash loop. Each entry below lists the comparison site and the constant value.

| Address in TLS | Field Being Checked | Constant Value |
| --- | --- | --- |
| `0x7FF93430FAE2` | `[return_address-0x908]` | `0xA228CC6A3A2FDB8B` |
| `0x7FF93430FB5F` | `NtCurrentPeb()` | `0xA228CC6AD6B12FBF` |
| `0x7FF934310623` | `PEB->Ldr` | `0xA228CC6A5EBA70A5` |
| `0x7FF934310670` | `TEB->glDispatchTable[106]` | `0xA228CC6AF40FF56F` |
| `0x7FF9343108DF` | `PEB->ProcessParameters` | `0xA228CC6A278DCC6D` |
| `0x7FF9343109AE` | Loader linked-list element | `0xA228CC6AB93136BB` |
| `0x7FF9343109EB` | Alternative PEB pointer mask | `0xA228CC6AE057D4FD` |
| `0x7FF934310A13` | PEB pointer reused in tear-down branch | `0xA228CC6AD6B12FBF` |
| `0x7FF934310A8F` | Loader lock hash | `0xA228CC6A2BCC4C1B` |
| `0x7FF934310C36` | Stage-4 decode guard | `0xA228CC6A37EF3627` |
| `0x7FF934310CFF` | Stage-4 decode guard | `0xA228CC6A4219167D` |
| `0x7FF934310D6C` | Stage-4 decode guard | `0xA228CC6A4443C895` |
| `0x7FF934310FB2` | Stage-4 decode guard | `0xA228CC6ABB9FA06B` |
| `0x7FF934310FE9` | Stage-4 decode guard | `0xA228CC6A8B6A9417` |
| `0x7FF934311710` | Pointer decode guard | `0xA228CC6A0A2D6B1D` |

The TLS code also masks PEB values with a family of `0xE2CA6A0B********` constants to ensure the pointers follow expected bit patterns:

| Address in TLS | Mask Value |
| --- | --- |
| `0x7FF93430FF6A` | `0xE2CA6A0B8F713ADD` |
| `0x7FF934310663` | `0xE2CA6A0B0E1C5AF1` |
| `0x7FF9343108FC` | `0xE2CA6A0B20F5277D` |
| `0x7FF9343109A1` | `0xE2CA6A0BC849E2E5` |
| `0x7FF934311507` | `0xE2CA6A0B20F5277D` |
| `0x7FF93431216C` | `0xE2CA6A0B64A45ACB` |

### 2. CPUID Usage
The TLS sequence issues the following CPUID leaves, always with ECX = 0 unless stated otherwise. Each leaf is paired with a specific check:

| Leaf Value | Address of `mov eax, imm` | CPUID Instruction | Purpose |
| --- | --- | --- | --- |
| `0x00000005` | `0x7FF93430FAD1` | `0x7FF93430FADB` | Basic cache parameters recorded for later comparison.
| `0x00000019` | `0x7FF93430FC3A` | `0x7FF93430FC44` | Hybrid topology snapshot saved for stage-2 validation.
| `0x40000006` | `0x7FF93430FCE7` | `0x7FF93430FCF1` | Hypervisor leaf; if `EAX & 0xFFFF` equals `0x0D30`, the process is terminated with status `0x00BADD00D`.
| `0x4000001A` | `0x7FF93431004B` | `0x7FF934310053` | Collects additional hypervisor capability bits.
| `0x00000011` | `0x7FF9343100FE` | `0x7FF934310108` | Gathers SMT/core topology ratios.
| `0x8000000F` | `0x7FF93431022F` | `0x7FF934310237` | Saves extended capabilities for later masking.

### 3. Crash Loop When a Sentinel Hits
If any pointer or CPUID test fails, execution lands in the crash scaffold beginning at `0x7FF9343103B3`. The loop repeatedly performs the sequence shown below, guaranteeing a controlled access violation:

```asm
loc_7FF9343103B3:
    imul r13d, dword ptr [rdi-0x6A50334B], 0x5712899D
    mov byte ptr ds:0x9D95AFCCB5AF6946, al
    mov [rdx], edx
    push rdi
    ; more writes to 0x9D95AFCCB51D6943 and 0xCCCCCCCCCCCCCCCC follow
```

The poison targets include the three constants `0x9D95AFCCB5AF6946`, `0x9D95AFCCB51D6943`, and `0xCCCCCCCCCCCCCCCC`.

### 4. Termination Paths
- Direct termination: `NtTerminateProcess(-1, 0x00BADD00D)` at `0x7FF93430FF52`.
- Detach termination: `NtTerminateProcess(-1, 0)` at `0x7FF934310277`.
- GS/stack cookie failure: `_report_securityfailure` (`0x7FF93439A00C`) and `_report_gsfailure` (`0x7FF93439A0C0`) terminate the process with `0xC0000409` after logging context.

---

## Stage Coordinator (`0x7FF93439A498`)

### Stage Argument 0 – Teardown Path (`sub_7FF93439A3C8`)
- Decrements `stru_7FF933870C20[310].__vftable` and only proceeds if it remains > 0.
- Calls `sub_7FF93439A78C` to retrieve the current loader fingerprint.
- Invokes `sub_7FF93439A98C`, `sub_7FF93439A6BC`, and `sub_7FF93439ABA4` to unregister callbacks, release instrumentation, and destroy auxiliary objects.
- Calls `sub_7FF93439A828` with `a2 = 0` to log a clean shutdown and runs `sub_7FF93439A9BC` for final bookkeeping before returning 1.

### Stage Argument 1 – Initialisation Path (`sub_7FF93439A2B0`)
- Calls `sub_7FF93439A7EC(0)` to set the stage armed flag.
  - `sub_7FF93439BDB8` allocates an FLS index via `sub_7FF9343A6424`. The FLS index is stored in `dword_7FF933870240`. The slot is populated with `sub_7FF9343A64FC`. Failure triggers `sub_7FF93439EC34` and returns 0.
  - `sub_7FF93439C1D0` processes the probe array `off_7FF933650CB0` with `sub_7FF9343A3BA8`. Each probe (detailed below) must succeed.
- Marks `stru_7FF933870C20[313].__vftable = 2` and, if `sub_7FF93439A958` succeeds, increments the active counter by calling the guard dispatcher at `sub_7FF93439AA10` and the callback initialiser `sub_7FF93439A6F4`.

### Stage Argument 2 – Deep Audit Path
- Directly invokes `sub_7FF9343762F0` with the stage set to 2. This function replays sentinel checks, validates CPUID 0x19 data, hashes loader entries, and registers a Process Instrumentation Callback.

### Stage Argument 3 – Final Cleanup (`sub_7FF93439A9F8`)
- Calls `sub_7FF93439C240`, `sub_7FF93439BE20`, and any outstanding destructors to unwind instrumentation.
- Invokes `sub_7FF93439A828` with `a2 = 0` and `sub_7FF93439A9BC` before returning 1.

---

## Probe Array (`off_7FF933650CB0`)
Each probe entry consists of an initialiser and a teardown callback invoked in the order below. All addresses are absolute within `dump.bin`.

| Entry | Initialiser | Teardown | Description |
| --- | --- | --- | --- |
| 0 | `sub_7FF93439C090` | — | Seeds `stru_7FF933870C20[497].__vftable` with the address of `unk_7FF933870790`.
| 1 | `sub_7FF93439C0E8` | `sub_7FF9343A1FDC` | The bootstrap sequence: reseeds `_security_cookie`, invokes `initp_misc_winsig`, sets up module metadata via `sub_7FF93439C940`, and logs loaded handles.
| 2 | `sub_7FF93439C0E0` | `sub_7FF93439C0E4` | Placeholder probes that always return 1, used to keep the structure stride.
| 3 | `sub_7FF9343A259C` | `sub_7FF9343A25E4` | Allocates 14 guarded critical sections using `InitializeCriticalSectionEx`. Each successful allocation increments `stru_7FF933870C20[424].__vftable`. The teardown deletes all sections and resets the counter.
| 4 | `sub_7FF9343A2654` | `sub_7FF9343A2670` | Stores the process heap handle in `stru_7FF933870C20[424].spare` via `GetProcessHeap` and clears it on teardown.
| 5 | `sub_7FF93439C128` | `sub_7FF93439BDE0` | Increments a global reference counter using an atomic `xadd`; when the counter reaches 1 the teardown runs `sub_7FF9343A3B6C` to free heap allocations and resets the guard pointer.
| 6 | `sub_7FF9343A267C` | `sub_7FF9343A26B8` | Allocates a dedicated FLS slot with destructor `Concurrency::details::SchedulerProxy::DeleteThis`. If `sub_7FF9343A2854` fails to return a scheduler context, the teardown frees the FLS slot immediately.

`sub_7FF9343A23E0` resolves all runtime APIs required by the probes. It walks an array of module names at `off_7FF9336517C0` (manifest-style `api-ms-win-*` and `ext-ms-*` strings) and caches `HMODULE` handles in `stru_7FF933870C20[362..372]`. Function pointers are stored in `stru_7FF933870C20[373..]` with `_security_cookie` obfuscation. On resolution failure the code marks the slot with `-1` so later lookups fall back to other DLLs.

---

## Deep Hardware and Loader Audit (`0x7FF9343762F0`)

### CPUID Leaf 0x19 Validation
- The function issues `cpuid eax=0x19` at `0x7FF934376363`. The result registers are decomposed into bitfields representing SMT width, core type, thread IDs, and VBMI capabilities.
- The code uses constant masks to isolate the fields (`shr`/`and` sequences at `0x7FF934376467` onwards) and folds them into 32-bit segments.
- The derived values are compared against an obfuscated reference table located at `0x7FF9338B41C2`. The table is stored as XOR/NOT/ROL encoded bytes; the decode loop at `0x7FF934310C80` uses the sequence `xor`, `not`, `rol 4` to recover the expected bytes.
- Any mismatch jumps to the crash path at `0x7FF934376A89`.

### Loader Fingerprint Hash
- The routine retrieves `TEB->Tib.ExceptionList`, `PEB->Ldr`, and the loader entry array at runtime.
- A series of hashed multiplications using the constants `0x334501270280FF5` and `0x800000001CB` combine the loader AVL entries into a unique hash. This hash is compared against a 16-byte signature stored alongside each loader entry.
- The comparison uses `movdqu` and `pmovmskb` at `0x7FF93437686A`; only a full 0xFFFF mask is accepted. Mismatches repeat the loop through the next entry until either the signature is found or the list terminates. Failure to find a match triggers the crash jump at `0x7FF93437694F`.

### System Call Instrumentation
1. **`NtQueryInformationProcess(ProcessBasicInformation)`**
   - System call prepared at `0x7FF934376703` with `ProcessHandle = -2`, `ProcessInformationClass = 1`, buffer size `0x20`.
   - The syscall number is not hard-coded. It is read from the obfuscated table at `0x7FF9338AE319`, addressed using a hash derived from `TEB->ClientId` and `PEB->GdiSharedHandleTable`.
   - The result is checked against cached parent PID, session ID, and `PEB` pointer expectations from earlier stages.
2. **`NtSetInformationProcess(ProcessInstrumentationCallback)`**
   - Prepared at `0x7FF9343769F5` with a stack structure containing a pointer to the instrumentation callback and mode flags.
   - The status register is forced to `0xC000012A` on failure. Any failure leads directly to the crash sequence, ensuring the instrumentation callback is registered exactly once.

### Additional Sentinel Checks
- Repeats the pointer sentinel comparisons with constants `0xA228CC6A20F32C1F`, `0xA228CC6A5707B10B`, `0xA228CC6A4443C895`, and `0xA228CC6ABB9FA06B`.
- Uses mask `0xE2CA6A0BE61BC733` at `0x7FF93437640C` to validate the combined loader pointer.

---

## Extended TLS Helper (`0x7FF9343105F0`)
This routine is called from the TLS path and reruns many of the pointer checks while decoding encrypted loader metadata.

- Decodes bytes from the table at `0x7FF9338B41C2` using the loop at `0x7FF934310C80`.
- Asserts multiple obfuscated constants (list in the TLS section) against PEB/TEB derived pointers.
- Uses the masks `0xE2CA6A0B20F5277D`, `0xE2CA6A0BC849E2E5`, and `0xE2CA6A0B64A45ACB` to ensure loader-derived values follow expected patterns.

Failure anywhere in this helper transfers control to the same crash stencil at `0x7FF9343103B3`.

---

## Crash and Fail-Fast Infrastructure

| Function | Address | Trigger | Termination Status |
| --- | --- | --- | --- |
| Crash scaffold | `0x7FF9343103B3` | Any sentinel mismatch or loader comparison failure | Access violation leading to WER dialog |
| Crash scaffold clone | `0x7FF934376A89` | Stage-2 failures | Access violation |
| `_report_securityfailure` | `0x7FF93439A00C` | GS cookie failure | `STATUS_STACK_BUFFER_OVERRUN (0xC0000409)` |
| `_report_gsfailure` | `0x7FF93439A0C0` | Guard stack failure | `0xC0000409` |
| `sub_7FF93439D388` | `0x7FF93439D388` | Unexpected `IsProcessorFeaturePresent(0x17)` state | `0xC0000417` after `__fastfail(5)` |
| `sub_7FF93439CA40` | `0x7FF93439CA40` | Guard failure during shutdown | `TerminateProcess` ? `ExitProcess` |
| Direct TLS kill | `0x7FF93430FF52` | DBVM CPUID signature | `0x00BADD00D` |
| Detach kill | `0x7FF934310277` | Stage-0 failure | `0x00000000` |

---

## Sentinel Constant Catalogue

### `0xA228CC6A********`
```
0xA228CC6A0A2D6B1D  (pointer decode guard)
0xA228CC6A20F32C1F  (stage-2 combined pointer check)
0xA228CC6A278DCC6D  (PEB parameters mask)
0xA228CC6A2BCC4C1B  (loader lock hash)
0xA228CC6A37EF3627  (stage-4 pointer guard)
0xA228CC6A3A2FDB8B  (TLS return-address check)
0xA228CC6A4219167D  (stage-4 pointer guard)
0xA228CC6A4443C895  (primary PEB/TEB sentinel)
0xA228CC6A5EBA70A5  (PEB->Ldr check)
0xA228CC6A5707B10B  (stage-2 loader mask)
0xA228CC6A8B6A9417  (stage-4 guard)
0xA228CC6AB93136BB  (loader pointer mask)
0xA228CC6ABB9FA06B  (TEB dispatch mask)
0xA228CC6AD6B12FBF  (PEB pointer check)
0xA228CC6AE057D4FD  (variant PEB mask)
0xA228CC6AF40FF56F  (TLS dispatch table mask)
```

### `0xE2CA6A0B********`
```
0xE2CA6A0B0E1C5AF1  (multiple pointer masks)
0xE2CA6A0B20F5277D  (loader hash mask)
0xE2CA6A0B64A45ACB  (stage-4 pointer mask)
0xE2CA6A0B8F713ADD  (TEB mask)
0xE2CA6A0BC849E2E5  (stage-4 pointer mask)
0xE2CA6A0BE61BC733  (stage-2 combined mask)
```

### Crash-Target Constants
```
0x9D95AFCCB51D6943
0x9D95AFCCB5AF6946
0xCCCCCCCCCCCCCCCC
```

---

## Direct Syscalls Observed

| Address | Syscall | Parameters | Notes |
| --- | --- | --- | --- |
| `0x7FF934376703` | `NtQueryInformationProcess(ProcessBasicInformation)` | `ProcessHandle = -2`, `ProcessInformation = &Buffer`, `ProcessInformationLength = 0x20` | Syscall number fetched from the hashed table at `0x7FF9338AE319`.
| `0x7FF9343769F5` | `NtSetInformationProcess(ProcessInstrumentationCallback)` | Structure at `rsp+0x20` populated with callback pointer, reserved fields set to zero | Failure forces crash loop. Uses hashed syscall ID.
| `0x7FF93439A278` | `_raise_securityfailure` | — | Calls `TerminateProcess(GetCurrentProcess(), 0xC0000409)`.
| `0x7FF93439CA40` | Guard kill | `TerminateProcess(GetCurrentProcess(), uExitCode)` followed by `ExitProcess(uExitCode)` | Used during abnormal shutdown detection.

The syscall hash uses the constants `0x334501270280FF5` and `0x800000001CB` to blend GDI and ClientId values into indices for the obfuscated syscall ID table at `0x7FF9338AE319`. The table is filled at runtime; in the raw dump it contains placeholder `0xCC` bytes.

---

## Global Structures and Counters
- `stru_7FF933870C20`: multi-purpose array storing API pointers, counters, loader fingerprints, and type descriptors. Notable indices:
  - `[222]`: stores CPUID capability flags (bitfield updated throughout TLS and stage 2).
  - `[310]`: stage activity counter manipulated in `sub_7FF93439A3C8` and `sub_7FF93439A2B0`.
  - `[313]`: stage state flag (0, 1, or 2) toggled during initialisation and teardown.
  - `[322]`: holds a type descriptor pointer initialised by `sub_7FF93439C940`.
  - `[362..372]`: cached `HMODULE` handles resolved by `sub_7FF9343A23E0`.
  - `[373+]`: obfuscated function pointers for dynamically imported APIs.
  - `[389..402]`: array of `CRITICAL_SECTION` objects created by `sub_7FF9343A259C`.
  - `[424].__vftable`: critical section allocation count.
  - `[424].spare`: process heap handle.
- `dword_7FF933870240`: stores the FLS index allocated by `sub_7FF93439EBEC` and freed by `sub_7FF93439EC34`.

---

## System Behaviour Summary
- Every pointer mask and CPUID check must succeed across TLS, stage-1, stage-2, and stage-3 invocations. No single failure is tolerated.
- The detector never silently returns false negatives: on any mismatch it deliberately corrupts memory so Windows reports a third-party interference error and generates a crash dump.
- The CPUID `0x40000006` leaf is the only superficial DBVM fingerprint. Later stages rely on pointer masks, loader hashes, and syscall instrumentation to confirm the presence of DBVM even if the hypervisor attempts to spoof the first check.
- The detector is entirely user-mode; it does not load a kernel driver. All operations occur before Roblox game code receives control.

---

## Research Notes and Potential Countermeasures
- Hypervisor developers must ensure `cpuid 0x40000006` returns a leaf that does not match DBVM’s signature while keeping the `0x19`, `0x11`, and `0x8000000F` leaves internally consistent. Any disagreement between leaf values surfaces in stage 2.
- Any hypervisor that rewrites loader lists, PEB pointers, or TLS return addresses must reproduce the exact bit patterns expected by the sentinel constants listed above. Failure to do so trips the crash scaffolds.
- Process Instrumentation Callback registration cannot be skipped. Either allow Hyperion to register its callback or emulate a successful `NtSetInformationProcess(ProcessInstrumentationCallback)` call without denying subsequent registrations.
- Patching the crash scaffold itself is non-trivial because the pointer sentinels also verify code sections. Alternative approaches include intercepting the WER reporting routine or forcing the detector to believe the crash loop ran even when it was bypassed.

---

This report captures every observable constant, function, and flow used in the Hyperion DBVM detector present in `dump.bin`. It is intended to be a self-contained reference for further research or defensive engineering.
