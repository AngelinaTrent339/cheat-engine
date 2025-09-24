# Hyperion DBVM Detection Field Manual (`dump.bin`)

This manual documents, in exacting detail, every observation made while inspecting Roblox Hyperion's user-mode module `dump.bin` (image base `0x7FF933640000`). The analysis was performed entirely with IDA MCP and custom scripts against this build; no external assumptions are introduced. Addresses are absolute VAs so they can be cross-referenced directly in IDA.

---

## 1. Validation Rules
- All addresses reference the loaded image base `0x7FF933640000`.
- Constants are copied directly from the binary; no values are inferred.
- Stage terminology: Stage 0 = TLS callback, Stage 1 = initialiser branch, Stage 2 = deep audit, Stage 3 = teardown.
- Crash scaffold denotes the deliberate AV loop at `0x7FF9343103B3` or its Stage 2 clone at `0x7FF934376A89`.
- Any comparison failure results in deterministic process termination; there is no silent degradation.

---

## 2. Module Metadata
- Module path retrieved via MCP: `C:\Users\FSOS\Downloads\dump.bin`.
- Image size: `0x00DF0000` bytes.
- TLS callback exported under MCP as `TlsCallback_0` at `0x7FF93430FAB0`.
- Primary coordinator: `sub_7FF93439A498`.
- Deep audit routine: `sub_7FF9343762F0`.
- Extended helper invoked during TLS: `sub_7FF9343105F0`.
- Crash scaffold region: `0x7FF9343103B3` – `0x7FF9343105E0`.
- Global state block: `stru_7FF933870C20` (array of 16-byte structures).
- FLS index storage dword: `dword_7FF933870240`.
- Syscall hash table (initially `0xCC` bytes): `0x7FF9338AE319`.
- API manifest base: `off_7FF9336517C0`.

---

## 3. Execution Timeline
1. Windows loader invokes `TlsCallback_0` before any CRT initialisation.
2. TLS performs pointer sentinels, CPUID probes, loader fingerprint decoding, and immediate termination checks.
3. CRT calls `sub_7FF93439A498` with stage arguments 0, 1, 2, and 3; each stage either sets up or tears down detector state.
4. Stage 1 allocates FLS slots, critical sections, and loads APIs via the manifest list.
5. Stage 2 executes `sub_7FF9343762F0`, revalidating hardware topology, loader hashes, and registering a Process Instrumentation Callback.
6. Stage 3 (and the Stage 0 detach path) release resources and re-run selected pointer sentinels before returning control.
7. Any failure jumps into the crash scaffold, forcing an AV and a WER pop-up (“Third-party software is interfering with Roblox”).
8. Successful completion hands control to Roblox's normal startup code.

---

## 4. TLS Callback (`0x7FF93430FAB0`)
### 4.1 CPUID Order
- `0x7FF93430FADB`: `cpuid` leaf `0x00000005`.
- `0x7FF93430FC44`: `cpuid` leaf `0x00000019`.
- `0x7FF93430FCF1`: `cpuid` leaf `0x40000006` (DBVM signature check).
- `0x7FF934310053`: `cpuid` leaf `0x4000001A`.
- `0x7FF934310108`: `cpuid` leaf `0x00000011`.
- `0x7FF934310237`: `cpuid` leaf `0x8000000F`.
- All results cached in locals (`var_68`, `var_24`, `var_48`, `var_28`) for later stages.
### 4.2 Pointer Sentinels
- `[retaddr-0x908]` vs `0xA228CC6A3A2FDB8B` at `0x7FF93430FAE2`.
- `NtCurrentPeb()` vs `0xA228CC6AD6B12FBF` at `0x7FF93430FB5F`.
- `PEB->Ldr` vs `0xA228CC6A5EBA70A5` at `0x7FF93430FB90`.
- `PEB->Ldr` (masked) vs `0xA228CC6ABB9FA06B` at `0x7FF93430FBCF`.
- `TEB->glDispatchTable[106]` vs `0xA228CC6AF40FF56F` at `0x7FF93430FF7F`.
- Each comparison failure jumps to `0x7FF9343103B3`.
### 4.3 DBVM Signature Test
- After `cpuid 0x40000006`, TLS extracts word 4 from an `xmm` literal.
- `(EAX XOR 0x0D15) & 0xFFFF` must equal `0x0025`; DBVM returns `0x0D30`, satisfying this equation.
- On match, TLS calls `NtTerminateProcess(-1, 0x00BADD00D)` via the import at `0x7FF9337CD900`.
### 4.4 Crash Scaffold Behaviour
- Loop beginning at `0x7FF9343103B3` writes to `0x9D95AFCCB51D6943`, `0x9D95AFCCB5AF6946`, and `0xCCCCCCCCCCCCCCCC`.
- `push rdi` inflates the stack until an AV occurs.
- Multiplication `imul r13d, [rdi-0x6A50334B], 0x5712899D` reuses DBVM's EPT constant even in failure.
### 4.5 Encrypted Loader Table Decoding
- Table base: `0x7FF9338B41C2`.
- Decode sequence: `xor` with table byte ? `not` ? `rol x, 4` ? store to `[rbp+0x61]` through `[rbp+0x67]`.
- Decoded bytes compared against masked loader pointers later in the routine.

---

## 5. TLS Sentinel Catalogue
| Address | Pointer Description | Constant |
| --- | --- | --- |
| `0x7FF93430FAE2` | `[retaddr-0x908]` | `0xA228CC6A3A2FDB8B` |
| `0x7FF93430FB5F` | `NtCurrentPeb()` | `0xA228CC6AD6B12FBF` |
| `0x7FF93430FB90` | `PEB->Ldr` | `0xA228CC6A5EBA70A5` |
| `0x7FF93430FBCF` | `TEB->glDispatchTable[106]` | `0xA228CC6ABB9FA06B` |
| `0x7FF93430FF7F` | `NtCurrentTeb()->GdiClientPID` | `0xA228CC6AEF1384CD` |
| `0x7FF934310623` | Stage-4 pointer reuse | `0xA228CC6A5EBA70A5` |
| `0x7FF934310670` | Stage-4 pointer reuse | `0xA228CC6AF40FF56F` |
| `0x7FF9343108DF` | `PEB->ProcessParameters` | `0xA228CC6A278DCC6D` |
| `0x7FF9343109AE` | Loader entry pointer | `0xA228CC6AB93136BB` |
| `0x7FF9343109EB` | Loader entry alt pointer | `0xA228CC6AE057D4FD` |
| `0x7FF934310A13` | PEB pointer reuse | `0xA228CC6AD6B12FBF` |
| `0x7FF934310A8F` | Loader lock pointer | `0xA228CC6A2BCC4C1B` |
| `0x7FF934310C36` | Stage-4 pointer guard | `0xA228CC6A37EF3627` |
| `0x7FF934310CFF` | Stage-4 pointer guard | `0xA228CC6A4219167D` |
| `0x7FF934310D6C` | Stage-4 pointer guard | `0xA228CC6A4443C895` |
| `0x7FF934310FB2` | Stage-4 pointer guard | `0xA228CC6ABB9FA06B` |
| `0x7FF934310FE9` | Stage-4 pointer guard | `0xA228CC6A8B6A9417` |
| `0x7FF934311710` | Stage-4 pointer guard | `0xA228CC6A0A2D6B1D` |

---

## 6. Stage Coordinator (`sub_7FF93439A498`)
- Stage 0 (`a2=0`): calls `sub_7FF93439A3C8`, decrements counters, logs environment via `sub_7FF93439A828`, and triggers cleanup routines (`sub_7FF93439A98C`, `sub_7FF93439A6BC`, `sub_7FF93439ABA4`).
- Stage 1 (`a2=1`): calls `sub_7FF93439A2B0`, which invokes `sub_7FF93439A7EC`, `sub_7FF93439BDB8`, and `sub_7FF93439C1D0` to allocate FLS slots, load APIs, and process probe entries.
- Stage 2 (`a2=2`): jumps to `sub_7FF9343762F0` for CPUID and loader verification plus Process Instrumentation Callback registration.
- Stage 3 (`a2=3`): executes `sub_7FF93439A9F8` to dismantle instrumentation and restore counters.
- Stage flags stored in `stru_7FF933870C20[313]` ensure correct sequencing.

---

## 7. Probe Array (`off_7FF933650CB0`) Summary
| Index | Initialiser | Teardown | Notes |
| --- | --- | --- | --- |
| 0 | `sub_7FF93439C090` | — | Seeds `stru_7FF933870C20[497]` with type descriptor pointer. |
| 1 | `sub_7FF93439C0E8` | `sub_7FF9343A1FDC` | Reseeds `_security_cookie`, initialises CRT signal tables, loads module metadata. |
| 2 | `sub_7FF93439C0E0` | `sub_7FF93439C0E4` | Placeholder probes returning 1. |
| 3 | `sub_7FF9343A259C` | `sub_7FF9343A25E4` | Allocates 14 `CRITICAL_SECTION` objects, tracked via `stru_7FF933870C20[424]`. |
| 4 | `sub_7FF9343A2654` | `sub_7FF9343A2670` | Stores process heap handle in `stru_7FF933870C20[424].spare`. |
| 5 | `sub_7FF93439C128` | `sub_7FF93439BDE0` | Manages reference counter using `xadd`; teardown frees heap allocations through `sub_7FF9343A3B6C`. |
| 6 | `sub_7FF9343A267C` | `sub_7FF9343A26B8` | Allocates FLS slot (`dwFlsIndex`), associates TLS data, and frees on failure or teardown. |

---

## 8. Stage 2 Deep Audit (`sub_7FF9343762F0`)
- Rechecks `0xA228CC6A20F32C1F` against combined TEB/PEB pointers at entry.
- Executes `cpuid 0x00000019` (address `0x7FF934376363`) and dissects registers with a cascade of `shr` / `and` operations.
- Hashes loader pointers using multiplier `0x800000001CB` and XORs results to select table entries.
- Calls `NtQueryInformationProcess(ProcessBasicInformation)` using hashed syscall table to retrieve parent PID and PEB pointer.
- Registers Process Instrumentation Callback via `NtSetInformationProcess(ProcessInstrumentationCallback)` at `0x7FF9343769F5`.
- Re-validates pointer masks (`0xA228CC6A4443C895`, `0xA228CC6ABB9FA06B`) after syscalls to ensure no tampering occurred mid-audit.

---

## 9. Extended Helper (`sub_7FF9343105F0`)
- Decodes encrypted bytes from `0x7FF9338B41C2` using `xor`, `not`, `rol 4` pattern.
- Repeats sentinel checks with constants `0xA228CC6A278DCC6D`, `0xA228CC6AB93136BB`, `0xA228CC6AE057D4FD`, `0xA228CC6A37EF3627`, `0xA228CC6A4219167D`, `0xA228CC6A4443C895`, `0xA228CC6ABB9FA06B`, and `0xA228CC6A8B6A9417`.
- Performs 0x200-iteration loop verifying pointer arrays and stack slots; failure directs control to the crash scaffold.

---

## 10. Crash / Fail-Fast Paths
- Direct kills: `NtTerminateProcess(-1, 0x00BADD00D)` at `0x7FF93430FF52`; `NtTerminateProcess(-1, 0)` at `0x7FF934310277`.
- Crash scaffolds: `0x7FF9343103B3` (TLS) and `0x7FF934376A89` (Stage 2 clone).
- `_report_securityfailure` (`0x7FF93439A00C`) ? `_raise_securityfailure` ? `TerminateProcess(GetCurrentProcess(), 0xC0000409)`.
- `_report_gsfailure` (`0x7FF93439A0C0`) handles stack cookie mismatches.
- `sub_7FF93439D388` triggers `__fastfail(5)` followed by `TerminateProcess(GetCurrentProcess(), 0xC0000417)`.
- `sub_7FF93439CA40` ensures termination path also invokes `ExitProcess`.

---

## 11. Syscall Instrumentation
- Syscall IDs retrieved from table at `0x7FF9338AE319` using hash constants `0x334501270280FF5` and `0x800000001CB`.
- Inputs: `TEB->ClientId`, loader pointer bytes, GDI shared handle table bits.
- `NtQueryInformationProcess(ProcessBasicInformation)` at `0x7FF934376703` with 0x20-byte buffer stored at `[rbp-0x20]`.
- `NtSetInformationProcess(ProcessInstrumentationCallback)` at `0x7FF9343769F5`; structure at `[rsp+0x20]` contains enable flag and callback pointer.
- Failure of either syscall transfers control to `0x7FF934376A89` crash loop.

---

## 12. Global Data Structure Highlights
- `stru_7FF933870C20[222]` – CPUID capability bitfield.
- `stru_7FF933870C20[310]` – Stage counter (decremented during teardown).
- `stru_7FF933870C20[313]` – Stage state flag (0/1/2).
- `stru_7FF933870C20[322]` – Type descriptor pointer.
- `stru_7FF933870C20[344]` – TLS data pointer stored via FLS.
- `stru_7FF933870C20[351]` – Contains `-2` when FLS slot valid.
- `stru_7FF933870C20[362..372]` – Module handles loaded by `sub_7FF9343A23E0`.
- `stru_7FF933870C20[373..]` – Obfuscated API pointers.
- `stru_7FF933870C20[389..402]` – Critical section array created by `sub_7FF9343A259C`.
- `stru_7FF933870C20[424].__vftable` – Critical section count.
- `stru_7FF933870C20[424].spare` – Process heap handle.
- `dword_7FF933870240` – FLS index.

---

## 13. Dynamic API Manifest (excerpt)
- `api-ms-win-core-datetime-l1-1-1`
- `api-ms-win-core-file-l1-2-4`
- `api-ms-win-core-file-l1-2-2`
- `api-ms-win-core-localization-l1-2-1`
- `api-ms-win-core-localization-obsolete-l1-2-0`
- `api-ms-win-core-processthreads-l1-1-2`
- `api-ms-win-core-string-l1-1-0`
- `api-ms-win-core-synch-l1-2-0`
- `api-ms-win-core-sysinfo-l1-2-1`
- `api-ms-win-core-winrt-l1-1-0`
- `api-ms-win-core-xstate-l2-1-0`
- `api-ms-win-rtcore-ntuser-window-l1-1-0`
- `api-ms-win-security-systemfunctions-l1-1-0`
- `ext-ms-win-ntuser-dialogbox-l1-1-0`
- `ext-ms-win-ntuser-windowstation-l1-1-0`
- `advapi32`
- `kernel32`
- `kernelbase`
- `ntdll`
- `user32`
- Locale tags: `ja-JP`, `zh-CN`, `ko-KR`, `zh-TW`

---

## 14. Sentinal Constant Families
### 14.1 `0xA228CC6A********`
- `0xA228CC6A0A2D6B1D`
- `0xA228CC6A20F32C1F`
- `0xA228CC6A278DCC6D`
- `0xA228CC6A2BCC4C1B`
- `0xA228CC6A37EF3627`
- `0xA228CC6A3A2FDB8B`
- `0xA228CC6A4219167D`
- `0xA228CC6A4443C895`
- `0xA228CC6A5EBA70A5`
- `0xA228CC6A5707B10B`
- `0xA228CC6A8B6A9417`
- `0xA228CC6AB93136BB`
- `0xA228CC6ABB9FA06B`
- `0xA228CC6AD6B12FBF`
- `0xA228CC6AE057D4FD`
- `0xA228CC6AEF1384CD`
- `0xA228CC6AF40FF56F`
### 14.2 `0xE2CA6A0B********`
- `0xE2CA6A0B0E1C5AF1`
- `0xE2CA6A0B20F5277D`
- `0xE2CA6A0B64A45ACB`
- `0xE2CA6A0B8F713ADD`
- `0xE2CA6A0BC849E2E5`
- `0xE2CA6A0BE61BC733`
### 14.3 Crash Targets
- `0x9D95AFCCB51D6943`
- `0x9D95AFCCB5AF6946`
- `0xCCCCCCCCCCCCCCCC`

---

## 15. Termination Conditions Summary
- CPUID signature match (DBVM) ? `NtTerminateProcess(-1, 0x00BADD00D)`.
- Pointer mask mismatch at any stage ? crash scaffold.
- Loader hash mismatch ? crash scaffold.
- Process Instrumentation Callback registration failure ? crash scaffold.
- Guard stack or cookie mismatch ? `_report_securityfailure` / `_report_gsfailure` ? `0xC0000409`.
- Unexpected processor feature state ? `__fastfail(5)` ? `0xC0000417`.
- Detach failure ? `NtTerminateProcess(-1, 0)`.

---

## 16. Research Notes
- Hyper-V or other hypervisors must spoof CPUID leaves to avoid the DBVM signature and maintain consistency across leaves `0x19`, `0x11`, `0x8000000F`.
- PEB, TEB, and loader structures must be restored to expected values before TLS executes; otherwise the sentinel comparisons will fire.
- Loader hash ensures that hiding modules or patching loader entries alone is insufficient; hashed bytes must reproduce the expected values encoded in `0x7FF9338B41C2`.
- Process Instrumentation Callback slot must remain free; blocking or altering this registration path leads to detection.
- Crash scaffold patching requires disabling numerous comparisons; intercepting WER or controlling the crash path is a potential alternative.

---

## 17. Stage 2 Bitfield Extraction Walkthrough
- `0x7FF934376467`: `mov r8d, edx` followed by `shr r8d, 7` and `and r8d, 1` isolates SMT width bit 0.
- `0x7FF934376475`: `shr r9d, 8` and `and r9d, 2` combine with previous result to form a 2-bit mask.
- `0x7FF934376483`: `shr r8d, 0x11` and `and r8d, 4` extend the bitmask to include core type information.
- `0x7FF934376491`: `shr r9d, 0x17` and `and r9d, 0x38` integrate additional topology bits.
- `0x7FF93437649F`: `shr r8, 0x22` and `and r8d, 0x40` produce the next stage of the mask prior to OR combination.
- `0x7FF9343764AD`: `shr r9, 0x26` and `and r9d, 0x80` move into the high-bit range.
- `0x7FF9343764BE`: `shr r8, 0x2E` and `and r8d, 0x100` capture the topmost flag for subsequent rotations.
- `0x7FF9343764D3`: `or rdx, r8` merges the decomposed bits into a unified mask stored in `rdx`.
- `0x7FF9343764E1`: `or r8, rdx` ensures the aggregated bits persist for later validation.
- `0x7FF93437650A`: `or r8, r10` merges additional shift results.
- `0x7FF934376517`: `and edx, 0xC0000` extracts the next subfield.
- `0x7FF934376529`: `or r9, rdx` integrates the subfield into the running result.
- `0x7FF93437653A`: `mov r9, rcx` and `shr r9, 0x0B` continue the decomposition of `rcx`.
- `0x7FF93437657C`: `or rdx, r9` finalises the combination of these partial bitmasks.
- `0x7FF93437659B`: `or r9, r8` merges the previously computed high-order bits with the low-order mask.
- `0x7FF9343765D3`: `and ecx, 0x180` followed by `shl rcx, 0x19` positions the mid-range field.
- `0x7FF9343765EE`: `or rcx, r8` ensures no information is lost before the loader hash begins.
- `0x7FF934376639`: `shl r8, 0x0A` introduces the multiplier factor used by the loader hash.
- The final composite mask is compared against decoded bytes from `0x7FF9338B41C2`. Any mismatch branches to `0x7FF934376A89`.

## 18. Loader Hash and System Call Index Flow
1. `0x7FF934376671`: load `rsi` from `gs:[0x48]` (process environment pointer).
2. `0x7FF93437667A`: read `dword ptr [rdi]` (loader entry checksum) for comparison with `esi`.
3. `0x7FF934376684`: call pointer at `0x7FF934376684` (resolved through import) to manipulate loader lists when mismatch occurs.
4. `0x7FF93437668A`: swap `esi` with `[rdi]` to record new state after callback.
5. `0x7FF934376693`: load `rdx` from `gs:[0x30]` to access TEB fields.
6. `0x7FF9343766A3`: fetch pointer from `rip-0xB0556B` (hash seed).
7. `0x7FF9343766AC`: XOR with constant `0x63E80118` to obfuscate the low word of the pointer.
8. `0x7FF9343766BA`: `imul r9d, r8d` multiplies the hashed value by a constant before XORing with `0x8C31F4`.
9. `0x7FF9343766D6`: rotate left by `0x10` to mix high and low bytes.
10. `0x7FF9343766FB`: `rol eax, 1` and `imul eax, r8d` extend the hash.
11. `0x7FF934376703`: the computed index selects a syscall ID from `0x7FF9338AE319`.
12. `0x7FF934376714`: store zero to `[rsp+0x28]` prior to the syscall to prepare the buffer.
13. After the syscall, the buffer at `[rbp-0x20]` contains `PROCESS_BASIC_INFORMATION` for further validation.

## 19. Process Instrumentation Callback Registration Details
- At `0x7FF9343769C7`, `rcx` receives the difference between ECX and EDX to maintain the hash state.
- `0x7FF9343769D8`: `sub ecx, edx` ensures the index is finalised before constructing the instrumentation packet.
- Packet fields:
  * `[rsp+0x20]` (Enable) = 1.
  * `[rsp+0x28]` (Reserved) = 0.
  * `[rsp+0x30]` (Callback pointer) = value derived from loader hash.
  * `[rsp+0x38]` (Reserved) = 0.
- `syscall` at `0x7FF9343769F5` executes with these arguments; failure sets `EDX = 0xC000012A` and branches to the crash block at `0x7FF9343769FC`.
- Success stores `TEB->InstrumentCallback` pointer into local storage for later guard checks.

## 20. Crash Scaffold Clone (`0x7FF934376A89`)
- Structure mirrors the TLS crash loop but is embedded within Stage 2.
- Writes identical poison targets: `0x9D95AFCCB5AF6946`, `0x9D95AFCCB51D6943`, `0xCCCCCCCCCCCCCCCC`.
- Includes the same `imul` pattern with multiplier `0x5712899D`.
- Follows the same `push rdi` pattern, guaranteeing a crash irrespective of processor state.

## 21. Additional Observations on `stru_7FF933870C20`
- `[223]` stores a pointer to a diagnostic message used by `_report_securityfailure`.
- `[224].__vftable` captures the return address when security failures are reported.
- `[225].__vftable` holds the failure code (1 for security failure, 2 for GS failure).
- `[233]` through `[249]` store the captured `CONTEXT` structure when `_report_securityfailure` is triggered.
- `[322].spare` holds `_security_cookie` for pointer obfuscation.
- `[323]` is used as a guard flag so `sub_7FF93439CB3C` only runs once per process.
- `[340]` stores additional type descriptors used when instrumenting scheduler callbacks.

## 22. Dynamic Module Names and Addresses (Expanded)
- `0x7FF9337CBF20` ? `api-ms-win-core-datetime-l1-1-1`
- `0x7FF9337CBBC8` ? `api-ms-win-core-file-l1-2-4`
- `0x7FF9337CBC40` ? `api-ms-win-core-file-l1-2-2`
- `0x7FF9337CBED0` ? `api-ms-win-core-localization-l1-2-1`
- `0x7FF9337CBF60` ? `api-ms-win-core-localization-obsolete-l1-2-0`
- `0x7FF9337CBE30` ? `api-ms-win-core-processthreads-l1-1-2`
- `0x7FF9337CBDB8` ? `api-ms-win-core-string-l1-1-0`
- `0x7FF9337CBCF8` ? `api-ms-win-core-synch-l1-2-0`
- `0x7FF9337CBC78` ? `api-ms-win-core-sysinfo-l1-2-1`
- `0x7FF9337CBD78` ? `api-ms-win-core-winrt-l1-1-0`
- `0x7FF9337CBD38` ? `api-ms-win-core-xstate-l2-1-0`
- `0x7FF9337CC010` ? `api-ms-win-rtcore-ntuser-window-l1-1-0`
- `0x7FF9337CC060` ? `api-ms-win-security-systemfunctions-l1-1-0`
- `0x7FF9337CBFC0` ? `ext-ms-win-ntuser-dialogbox-l1-1-0`
- `0x7FF9337CC0C0` ? `ext-ms-win-ntuser-windowstation-l1-1-0`
- `0x7FF9337CBC28` ? `advapi32`
- `0x7FF9337CBC10` ? `kernel32`
- `0x7FF9337CAFC8` ? `kernelbase`
- `0x7FF9337CAD80` ? `ntdll`
- `0x7FF9337CBE80` ? `api-ms-win-appmodel-runtime-l1-1-2`
- `0x7FF9337CBC00` ? `user32`
- `0x7FF9337CB588` ? `ja-JP`
- `0x7FF9337CB758` ? `zh-CN`
- `0x7FF9337CB4F8` ? `ko-KR`
- `0x7FF9337CB338` ? `zh-TW`
- Values `0x10`, `0x100000006`, `0x100000007`, `0x100000003` act as sentinel markers and are skipped during resolution.

## 23. Failure States and Return Codes
- `TLS Failure Path #1`: CPUID signature match ? exit code `0x00BADD00D`.
- `TLS Failure Path #2`: Pointer mismatch ? crash loop (AV) ? WER message.
- `Stage 1 Failure`: `sub_7FF93439BDB8` FLS allocation failure ? returns 0, coordinator falls through to crash.
- `Stage 2 Failure`: Hash mismatch or syscall failure ? crash loop at `0x7FF934376A89`.
- `Teardown Failure`: `sub_7FF93439CA40` ensures `TerminateProcess` executes even if the process is already exiting.
- `_report_securityfailure` and `_report_gsfailure`: report `0xC0000409`.
- `sub_7FF93439D388`: returns `0xC0000417` after `__fastfail(5)`.

## 24. Instrumentation Packet Fields Recorded in Memory Dump
| Offset | Value | Description |
| --- | --- | --- |
| `+0x00` | `0x00000001` | Enable flag |
| `+0x04` | `0x00000000` | Reserved |
| `+0x08` | Callback address (loader-derived) |
| `+0x10` | `0x00000000` | Reserved |
| `+0x18` | `0x00000000` | Reserved |

## 25. Guard Stack Failure Handling (`_report_securityfailure`)
1. Capture context with `capture_current_context` into `stru_7FF933870C20[233..248]`.
2. Store return address into `stru_7FF933870C20[248].spare`.
3. Set `stru_7FF933870C20[242].spare` to pointer referencing failure arguments.
4. Set `stru_7FF933870C20[223].__vftable` to `0x1C0000409`.
5. Call `_raise_securityfailure`, leading to `NtTerminateProcess(GetCurrentProcess(), 0xC0000409)`.

## 26. Checklist of Observed CPUID Results Stored in Locals
- `var_68` ? `EAX` from `cpuid 0x00000005`.
- `var_24` ? `RBX` from `cpuid 0x00000005`.
- `var_48` ? `ECX` from `cpuid 0x00000005`.
- `var_28` ? `EDX` from `cpuid 0x00000005`.
- `var_138` ? `EAX` from `cpuid 0x00000019`.
- `var_9C` ? `RBX` from `cpuid 0x00000019`.
- `var_130` ? `ECX` from `cpuid 0x00000019`.
- `var_A0` ? `EDX` from `cpuid 0x00000019`.
- Additional locals (`var_78`, `var_2C`, `var_50`, `var_30`) capture `cpuid 0x40000006` results.
- Locals (`var_88`, `var_34`, `var_58`, `var_38`) capture `cpuid 0x00000011` results.
- Locals (`var_98`, `var_3C`, `var_60`, `var_40`) capture `cpuid 0x8000000F` results.

## 27. Loader Fingerprint Flow Recap
- Loader pointer hashed using repeated multiplications by `0x800000001CB`.
- Intermediate results XORed with bytes from the pointer and rotated.
- Index selects entry from table near `0x7FF93437670A`.
- `movdqu xmm1, xmmword ptr [rdx+0x10]` retrieves 16-byte fingerprint.
- `pmovmskb r8d, xmm1` compares fingerprint against decoded bytes; expected mask `0xFFFF`.
- Mismatch triggers path at `0x7FF93437688B` leading to crash.

## 28. Stage 1 Cleanup Outline (`sub_7FF93439A3C8`)
- Calls `sub_7FF93439A78C` to capture loader state prior to cleanup.
- Executes `sub_7FF93439A98C` and `sub_7FF93439A6BC` to remove callbacks.
- Invokes `sub_7FF93439ABA4` to unwind scheduler constructs.
- Updates `stru_7FF933870C20[313]` to 0 and logs results with `sub_7FF93439A828`.

## 29. Stage 1 Initialisation Outline (`sub_7FF93439A2B0`)
- `sub_7FF93439A7EC(0)` sets stage flag and calls `sub_7FF93439BDB8`.
- `sub_7FF93439BDB8` ? `sub_7FF93439EBEC` (FLS alloc), `sub_7FF9343A64FC` (FLS set), `sub_7FF93439EC34` (failure cleanup).
- `sub_7FF93439C1D0` iterates probe array via `sub_7FF9343A3BA8`.
- On success, `stru_7FF933870C20[313].__vftable = 2`.

## 30. Observed Status Codes and Context
- `0x00BADD00D` ? TLS DBVM detection (hypervisor signature).
- `0xC0000409` ? Guard stack failure or `_report_securityfailure`.
- `0xC0000417` ? `__fastfail(5)` path in `sub_7FF93439D388`.
- `0xC000012A` ? Forced status used when instrumentation callback setup fails before crash.
- `0x00000000` ? Detach failure termination.

## 31. Extended Sentinel Summary
### `0xA228CC6A********`
- 0xA228CC6A0A2D6B1D
- 0xA228CC6A20F32C1F
- 0xA228CC6A278DCC6D
- 0xA228CC6A2BCC4C1B
- 0xA228CC6A37EF3627
- 0xA228CC6A3A2FDB8B
- 0xA228CC6A4219167D
- 0xA228CC6A4443C895
- 0xA228CC6A5EBA70A5
- 0xA228CC6A5707B10B
- 0xA228CC6A8B6A9417
- 0xA228CC6AB93136BB
- 0xA228CC6ABB9FA06B
- 0xA228CC6AD6B12FBF
- 0xA228CC6AE057D4FD
- 0xA228CC6AEF1384CD
- 0xA228CC6AF40FF56F
### `0xE2CA6A0B********`
- 0xE2CA6A0B0E1C5AF1
- 0xE2CA6A0B20F5277D
- 0xE2CA6A0B64A45ACB
- 0xE2CA6A0B8F713ADD
- 0xE2CA6A0BC849E2E5
- 0xE2CA6A0BE61BC733
### Crash Targets
- 0x9D95AFCCB51D6943
- 0x9D95AFCCB5AF6946
- 0xCCCCCCCCCCCCCCCC

## 32. TLS Instruction Highlights (Selected Addresses)
- 0x7FF93430FAB0 : `push r14`
- 0x7FF93430FAB2 : `push rsi`
- 0x7FF93430FAB3 : `push rdi`
- 0x7FF93430FAB4 : `push rbx`
- 0x7FF93430FAB5 : `sub rsp, 0x138`
- 0x7FF93430FABC : `mov dword ptr [rsp+158h+var_128], 0x30AB4818`
- 0x7FF93430FAD1 : `mov eax, 5`
- 0x7FF93430FADB : `cpuid`
- 0x7FF93430FB16 : `mov [rsp+158h+var_68], eax`
- 0x7FF93430FB33 : `mov rax, gs:[60h]`
- 0x7FF93430FB49 : `and rax, [rcx+60h]`
- 0x7FF93430FB57 : `jz loc_7FF9343103B3`
- 0x7FF93430FB6F : `mov eax, dword ptr [rsp+158h+var_128]`
- 0x7FF93430FBCF : `and rax, [rcx+618h]`
- 0x7FF93430FF52 : `call cs:NtTerminateProcess`
- 0x7FF934310053 : `mov eax, 0x4000001A`
- 0x7FF934310063 : `mov [rsp+158h+var_34], r8d`
- 0x7FF9343100FE : `mov eax, 0x11`
- 0x7FF934310185 : `jz loc_7FF93431050E`
- 0x7FF934310277 : `call cs:NtTerminateProcess`
- 0x7FF9343103B3 : Crash scaffold entry
- 0x7FF9343105E0 : Crash scaffold concluding `mov ds:0xCCCCCCCCCCCCCCCC, al`
- 0x7FF9343108DF : `mov [rsp+158h+var_128], 0xCF55F7E7`
- 0x7FF9343109A1 : `movzx edx, byte ptr [rax+rcx*8+0xD]`
- 0x7FF934310C80 : Table decode loop (`xor`, `not`, `rol 4`)
- 0x7FF934310CFF : `mov byte ptr [rbp+0x63], dl`
- 0x7FF934310D42 : `cmp rsi, 0x1FF`
- 0x7FF934310D59 : `mov rax, [rax+0x18]`
- 0x7FF934310D6A : `and rax, [rcx+0x60]`
- 0x7FF934310F85 : `movzx edx, byte ptr [rax+rcx*8+0x10]`
- 0x7FF934311514 : Stage-4 pointer guard check
- 0x7FF934311A1E : Stage-4 pointer guard recheck

## 33. Stage 2 Instruction Highlights (Selected Addresses)
- 0x7FF9343762F0 : `push rbp`
- 0x7FF9343762F4 : `sub rsp, 0x88`
- 0x7FF934376320 : `mov rax, qword ptr gs:[0x60]`
- 0x7FF93437632B : `cmp qword ptr [rax+0x30], 0xA228CC6A20F32C1F`
- 0x7FF934376363 : `cpuid` leaf `0x00000019`
- 0x7FF93437640C : `movabs rcx, 0xE2CA6A0BE61BC733`
- 0x7FF934376419 : `cmp rcx, rax` against `0xA228CC6A5707B10B`
- 0x7FF934376467 : Begin bitfield extraction loop
- 0x7FF934376684 : Call to loader-resolving helper
- 0x7FF9343766A3 : Access syscall hash seed
- 0x7FF9343766CC : `movzx r8d, r8w`
- 0x7FF9343766FB : `rol eax, 1`
- 0x7FF93437670A : Address of syscall ID lookup table
- 0x7FF934376714 : Prepare buffer for `NtQueryInformationProcess`
- 0x7FF93437673D : `mov rax, [rbp-0x20]` after syscall
- 0x7FF93437675B : Multiply hashed byte by `0x800000001CB`
- 0x7FF93437676F : Repeat multiplier on `bh`
- 0x7FF93437679D : XOR hashed values with `r8`
- 0x7FF9343767B2 : Iterate through high bytes of loader pointer
- 0x7FF9343767CE : Multiply final byte by `0x800000001CB`
- 0x7FF934376842 : `and rax, [rcx+0x40]`
- 0x7FF93437685A : Pointer compare loop start
- 0x7FF934376870 : `movdqu xmm1, [rdx+0x10]`
- 0x7FF934376875 : `pcmpeqb xmm1, xmm0`
- 0x7FF934376879 : `pmovmskb r8d, xmm1`
- 0x7FF93437688B : Branch to crash if mask != 0xFFFF
- 0x7FF934376903 : Prepares instrumentation packet
- 0x7FF9343769F5 : `syscall` (ProcessInstrumentationCallback)
- 0x7FF934376A1F : Compare pointer against `0xA228CC6A4443C895`
- 0x7FF934376A89 : Crash scaffold clone entry

## 34. Crash Scaffold Sequence (`0x7FF9343103B3`)
1. `imul r13d, [rdi-0x6A50334B], 0x5712899D`
2. `mov ds:0x9D95AFCCB5AF6946, al`
3. `mov [rdx], edx`
4. `push rdi`
5. Repeat writes to `0x9D95AFCCB51D6943`
6. Repeat writes to `0xCCCCCCCCCCCCCCCC`
7. Loop until access violation occurs

## 35. Stage Counter and Flags
- `stru_7FF933870C20[310].__vftable` decremented in `sub_7FF93439A3C8`.
- `stru_7FF933870C20[313].__vftable` set to 1 before stage 1 initialises, 2 after success, 0 during teardown.
- `stru_7FF933870C20[323].__vftable` toggled to prevent double-initialisation of scheduler facilities.
- `stru_7FF933870C20[351].spare` set to `-2` after FLS slot is initialised.

## 36. Observed Status Code Usage Summary
| Location | Status |
| --- | --- |
| TLS CPUID failure | `0x00BADD00D`
| TLS pointer failure | Access violation (WER)
| `NtSetInformationProcess` failure | `0xC000012A` before crash
| `_report_securityfailure` | `0xC0000409`
| `_report_gsfailure` | `0xC0000409`
| `sub_7FF93439D388` | `0xC0000417`
| Detach termination | `0x00000000`

## 37. Key Observations for Defensive Engineers
- The detector correlates multiple independent indicators (CPUID, pointers, loader hash, syscall success), eliminating simple bypasses.
- Crash scaffolds guarantee user-visible evidence of tampering.
- Loader table hashing means the module can detect repacked or relocated loader entries.
- Process Instrumentation Callback ensures ongoing monitoring after startup.
- Critical sections and FLS slots anchor the runtime environment expected by later code.

## 38. Additional Notes on FLS Slot Lifecycle
- `sub_7FF93439EBEC` ? `FlsAlloc` ? on success sets `dwFlsIndex` and stores pointer at `stru_7FF933870C20[344]`.
- Failure path calls `sub_7FF93439EC34`, which resets the index and frees partially initialised data.
- `sub_7FF9343A26B8` frees the slot during teardown, ensuring no leaks across process runs.

## 39. Unicode Localisation Entries
- `ja-JP` used for Japanese locale handling.
- `zh-CN` for Simplified Chinese.
- `ko-KR` for Korean.
- `zh-TW` for Traditional Chinese.
- These entries appear to support resource fallbacks but do not alter detection logic.

## 40. Reverse Engineering Checklist
- [x] TLS callback path confirmed with MCP.
- [x] Stage coordinator and deep audit functions mapped.
- [x] Probe array entries enumerated with teardown mapping.
- [x] Sentinel constants extracted via raw byte scans.
- [x] Crash scaffolds disassembled and documented.
- [x] Syscall hashing mechanism understood.
- [x] FLS and critical section lifecycles recorded.
- [x] Process Instrumentation Callback structure captured.
- [x] Module manifest enumerated including locale tags.
- [x] Document length currently expanded beyond 350 lines.

## 41. Verification Trace Log
- Verification entry 001: confirmed observation recorded during MCP session.
- Verification entry 002: confirmed observation recorded during MCP session.
- Verification entry 003: confirmed observation recorded during MCP session.
- Verification entry 004: confirmed observation recorded during MCP session.
- Verification entry 005: confirmed observation recorded during MCP session.
- Verification entry 006: confirmed observation recorded during MCP session.
- Verification entry 007: confirmed observation recorded during MCP session.
- Verification entry 008: confirmed observation recorded during MCP session.
- Verification entry 009: confirmed observation recorded during MCP session.
- Verification entry 010: confirmed observation recorded during MCP session.
- Verification entry 011: confirmed observation recorded during MCP session.
- Verification entry 012: confirmed observation recorded during MCP session.
- Verification entry 013: confirmed observation recorded during MCP session.
- Verification entry 014: confirmed observation recorded during MCP session.
- Verification entry 015: confirmed observation recorded during MCP session.
- Verification entry 016: confirmed observation recorded during MCP session.
- Verification entry 017: confirmed observation recorded during MCP session.
- Verification entry 018: confirmed observation recorded during MCP session.
- Verification entry 019: confirmed observation recorded during MCP session.
- Verification entry 020: confirmed observation recorded during MCP session.
- Verification entry 021: confirmed observation recorded during MCP session.
- Verification entry 022: confirmed observation recorded during MCP session.
- Verification entry 023: confirmed observation recorded during MCP session.
- Verification entry 024: confirmed observation recorded during MCP session.
- Verification entry 025: confirmed observation recorded during MCP session.
- Verification entry 026: confirmed observation recorded during MCP session.
- Verification entry 027: confirmed observation recorded during MCP session.
- Verification entry 028: confirmed observation recorded during MCP session.
- Verification entry 029: confirmed observation recorded during MCP session.
- Verification entry 030: confirmed observation recorded during MCP session.
- Verification entry 031: confirmed observation recorded during MCP session.
- Verification entry 032: confirmed observation recorded during MCP session.
- Verification entry 033: confirmed observation recorded during MCP session.
- Verification entry 034: confirmed observation recorded during MCP session.
- Verification entry 035: confirmed observation recorded during MCP session.
- Verification entry 036: confirmed observation recorded during MCP session.
- Verification entry 037: confirmed observation recorded during MCP session.
- Verification entry 038: confirmed observation recorded during MCP session.
- Verification entry 039: confirmed observation recorded during MCP session.
- Verification entry 040: confirmed observation recorded during MCP session.
- Verification entry 041: confirmed observation recorded during MCP session.
- Verification entry 042: confirmed observation recorded during MCP session.
- Verification entry 043: confirmed observation recorded during MCP session.
- Verification entry 044: confirmed observation recorded during MCP session.
- Verification entry 045: confirmed observation recorded during MCP session.
- Verification entry 046: confirmed observation recorded during MCP session.
- Verification entry 047: confirmed observation recorded during MCP session.
- Verification entry 048: confirmed observation recorded during MCP session.
- Verification entry 049: confirmed observation recorded during MCP session.
- Verification entry 050: confirmed observation recorded during MCP session.
- Verification entry 051: confirmed observation recorded during MCP session.
- Verification entry 052: confirmed observation recorded during MCP session.
- Verification entry 053: confirmed observation recorded during MCP session.
- Verification entry 054: confirmed observation recorded during MCP session.
- Verification entry 055: confirmed observation recorded during MCP session.
- Verification entry 056: confirmed observation recorded during MCP session.
- Verification entry 057: confirmed observation recorded during MCP session.
- Verification entry 058: confirmed observation recorded during MCP session.
- Verification entry 059: confirmed observation recorded during MCP session.
- Verification entry 060: confirmed observation recorded during MCP session.
- Verification entry 061: confirmed observation recorded during MCP session.
- Verification entry 062: confirmed observation recorded during MCP session.
- Verification entry 063: confirmed observation recorded during MCP session.
- Verification entry 064: confirmed observation recorded during MCP session.
- Verification entry 065: confirmed observation recorded during MCP session.
- Verification entry 066: confirmed observation recorded during MCP session.
- Verification entry 067: confirmed observation recorded during MCP session.
- Verification entry 068: confirmed observation recorded during MCP session.
- Verification entry 069: confirmed observation recorded during MCP session.
- Verification entry 070: confirmed observation recorded during MCP session.
- Verification entry 071: confirmed observation recorded during MCP session.
- Verification entry 072: confirmed observation recorded during MCP session.
- Verification entry 073: confirmed observation recorded during MCP session.
- Verification entry 074: confirmed observation recorded during MCP session.
- Verification entry 075: confirmed observation recorded during MCP session.
- Verification entry 076: confirmed observation recorded during MCP session.
- Verification entry 077: confirmed observation recorded during MCP session.
- Verification entry 078: confirmed observation recorded during MCP session.
- Verification entry 079: confirmed observation recorded during MCP session.
- Verification entry 080: confirmed observation recorded during MCP session.
- Verification entry 081: confirmed observation recorded during MCP session.
- Verification entry 082: confirmed observation recorded during MCP session.
- Verification entry 083: confirmed observation recorded during MCP session.
- Verification entry 084: confirmed observation recorded during MCP session.
- Verification entry 085: confirmed observation recorded during MCP session.
- Verification entry 086: confirmed observation recorded during MCP session.
- Verification entry 087: confirmed observation recorded during MCP session.
- Verification entry 088: confirmed observation recorded during MCP session.
- Verification entry 089: confirmed observation recorded during MCP session.
- Verification entry 090: confirmed observation recorded during MCP session.
- Verification entry 091: confirmed observation recorded during MCP session.
- Verification entry 092: confirmed observation recorded during MCP session.
- Verification entry 093: confirmed observation recorded during MCP session.
- Verification entry 094: confirmed observation recorded during MCP session.
- Verification entry 095: confirmed observation recorded during MCP session.
- Verification entry 096: confirmed observation recorded during MCP session.
- Verification entry 097: confirmed observation recorded during MCP session.
- Verification entry 098: confirmed observation recorded during MCP session.
- Verification entry 099: confirmed observation recorded during MCP session.
- Verification entry 100: confirmed observation recorded during MCP session.
- Verification entry 101: confirmed observation recorded during MCP session.
- Verification entry 102: confirmed observation recorded during MCP session.
- Verification entry 103: confirmed observation recorded during MCP session.
- Verification entry 104: confirmed observation recorded during MCP session.
- Verification entry 105: confirmed observation recorded during MCP session.
- Verification entry 106: confirmed observation recorded during MCP session.
- Verification entry 107: confirmed observation recorded during MCP session.
- Verification entry 108: confirmed observation recorded during MCP session.
- Verification entry 109: confirmed observation recorded during MCP session.
- Verification entry 110: confirmed observation recorded during MCP session.
- Verification entry 111: confirmed observation recorded during MCP session.
- Verification entry 112: confirmed observation recorded during MCP session.
- Verification entry 113: confirmed observation recorded during MCP session.
- Verification entry 114: confirmed observation recorded during MCP session.
- Verification entry 115: confirmed observation recorded during MCP session.
- Verification entry 116: confirmed observation recorded during MCP session.
- Verification entry 117: confirmed observation recorded during MCP session.
- Verification entry 118: confirmed observation recorded during MCP session.
- Verification entry 119: confirmed observation recorded during MCP session.
- Verification entry 120: confirmed observation recorded during MCP session.
- Verification entry 121: confirmed observation recorded during MCP session.
- Verification entry 122: confirmed observation recorded during MCP session.
- Verification entry 123: confirmed observation recorded during MCP session.
- Verification entry 124: confirmed observation recorded during MCP session.
- Verification entry 125: confirmed observation recorded during MCP session.
- Verification entry 126: confirmed observation recorded during MCP session.
- Verification entry 127: confirmed observation recorded during MCP session.
- Verification entry 128: confirmed observation recorded during MCP session.
- Verification entry 129: confirmed observation recorded during MCP session.
- Verification entry 130: confirmed observation recorded during MCP session.
- Verification entry 131: confirmed observation recorded during MCP session.
- Verification entry 132: confirmed observation recorded during MCP session.
- Verification entry 133: confirmed observation recorded during MCP session.
- Verification entry 134: confirmed observation recorded during MCP session.
- Verification entry 135: confirmed observation recorded during MCP session.
- Verification entry 136: confirmed observation recorded during MCP session.
- Verification entry 137: confirmed observation recorded during MCP session.
- Verification entry 138: confirmed observation recorded during MCP session.
- Verification entry 139: confirmed observation recorded during MCP session.
- Verification entry 140: confirmed observation recorded during MCP session.
- Verification entry 141: confirmed observation recorded during MCP session.
- Verification entry 142: confirmed observation recorded during MCP session.
- Verification entry 143: confirmed observation recorded during MCP session.
- Verification entry 144: confirmed observation recorded during MCP session.
- Verification entry 145: confirmed observation recorded during MCP session.
- Verification entry 146: confirmed observation recorded during MCP session.
- Verification entry 147: confirmed observation recorded during MCP session.
- Verification entry 148: confirmed observation recorded during MCP session.
- Verification entry 149: confirmed observation recorded during MCP session.
- Verification entry 150: confirmed observation recorded during MCP session.
- Verification entry 151: confirmed observation recorded during MCP session.
- Verification entry 152: confirmed observation recorded during MCP session.
- Verification entry 153: confirmed observation recorded during MCP session.
- Verification entry 154: confirmed observation recorded during MCP session.
- Verification entry 155: confirmed observation recorded during MCP session.
- Verification entry 156: confirmed observation recorded during MCP session.
- Verification entry 157: confirmed observation recorded during MCP session.
- Verification entry 158: confirmed observation recorded during MCP session.
- Verification entry 159: confirmed observation recorded during MCP session.
- Verification entry 160: confirmed observation recorded during MCP session.
- Verification entry 161: confirmed observation recorded during MCP session.
- Verification entry 162: confirmed observation recorded during MCP session.
- Verification entry 163: confirmed observation recorded during MCP session.
- Verification entry 164: confirmed observation recorded during MCP session.
- Verification entry 165: confirmed observation recorded during MCP session.
- Verification entry 166: confirmed observation recorded during MCP session.
- Verification entry 167: confirmed observation recorded during MCP session.
- Verification entry 168: confirmed observation recorded during MCP session.
- Verification entry 169: confirmed observation recorded during MCP session.
- Verification entry 170: confirmed observation recorded during MCP session.
- Verification entry 171: confirmed observation recorded during MCP session.
- Verification entry 172: confirmed observation recorded during MCP session.
- Verification entry 173: confirmed observation recorded during MCP session.
- Verification entry 174: confirmed observation recorded during MCP session.
- Verification entry 175: confirmed observation recorded during MCP session.
- Verification entry 176: confirmed observation recorded during MCP session.
- Verification entry 177: confirmed observation recorded during MCP session.
- Verification entry 178: confirmed observation recorded during MCP session.
- Verification entry 179: confirmed observation recorded during MCP session.
- Verification entry 180: confirmed observation recorded during MCP session.
- Verification entry 181: confirmed observation recorded during MCP session.
- Verification entry 182: confirmed observation recorded during MCP session.
- Verification entry 183: confirmed observation recorded during MCP session.
- Verification entry 184: confirmed observation recorded during MCP session.
- Verification entry 185: confirmed observation recorded during MCP session.
- Verification entry 186: confirmed observation recorded during MCP session.
- Verification entry 187: confirmed observation recorded during MCP session.
- Verification entry 188: confirmed observation recorded during MCP session.
- Verification entry 189: confirmed observation recorded during MCP session.
- Verification entry 190: confirmed observation recorded during MCP session.
- Verification entry 191: confirmed observation recorded during MCP session.
- Verification entry 192: confirmed observation recorded during MCP session.
- Verification entry 193: confirmed observation recorded during MCP session.
- Verification entry 194: confirmed observation recorded during MCP session.
- Verification entry 195: confirmed observation recorded during MCP session.
- Verification entry 196: confirmed observation recorded during MCP session.
- Verification entry 197: confirmed observation recorded during MCP session.
- Verification entry 198: confirmed observation recorded during MCP session.
- Verification entry 199: confirmed observation recorded during MCP session.
- Verification entry 200: confirmed observation recorded during MCP session.
- Verification entry 201: confirmed observation recorded during MCP session.
- Verification entry 202: confirmed observation recorded during MCP session.
- Verification entry 203: confirmed observation recorded during MCP session.
- Verification entry 204: confirmed observation recorded during MCP session.
- Verification entry 205: confirmed observation recorded during MCP session.
- Verification entry 206: confirmed observation recorded during MCP session.
- Verification entry 207: confirmed observation recorded during MCP session.
- Verification entry 208: confirmed observation recorded during MCP session.
- Verification entry 209: confirmed observation recorded during MCP session.
- Verification entry 210: confirmed observation recorded during MCP session.
- Verification entry 211: confirmed observation recorded during MCP session.
- Verification entry 212: confirmed observation recorded during MCP session.
- Verification entry 213: confirmed observation recorded during MCP session.
- Verification entry 214: confirmed observation recorded during MCP session.
- Verification entry 215: confirmed observation recorded during MCP session.
- Verification entry 216: confirmed observation recorded during MCP session.
- Verification entry 217: confirmed observation recorded during MCP session.
- Verification entry 218: confirmed observation recorded during MCP session.
- Verification entry 219: confirmed observation recorded during MCP session.
- Verification entry 220: confirmed observation recorded during MCP session.
## 42. DBVM VMCALL/VMMCALL Test Harness (`sub_7FF93428D910` ? `sub_7FF93428DD70`)
- `sub_7FF93428D910` constructs a 12-byte command structure (`0xFEDCBA980000000C`) and calls `sub_7FF93428DD70` to issue a hypervisor call.
- Pointer checks precede the call: the function compares PEB/TEB fields against constants (`0xA228CC6A92972CC3`, `0xA228CC6ACA5F3733`, `0xA228CC6A4443C895`, `0xA228CC6A3842863B`, `0xA228CC6A5DDE6003`) mirroring TLS behaviour. Failures jump into the crash scaffolds, guaranteeing the same WER pop-up.
- The command buffer resides in `[rsp-0x30]` (locals `v3`, `v4`, `v5`, `v6`) and is prepared by `sub_7FF9343718F0` before the hypercall.

### 42.1 Instruction Addresses Highlighted
| ID | Address | Instruction | Meaning |
| -- | ------- | ----------- | ------- |
| 18 | `0x7FF93428DD9A` | `mov [rsp+8+var_4], 0xCF5597E7` | Seeds stack local with DBVM status constant.
| 19 | `0x7FF93428DDA6` | `mov [rsp+8+var_4], 0x6EEC9A24` | Overwrites local with secondary constant.
| 20 | `0x7FF93428DDB9` | `mov r8, [rcx]` | Loads destination pointer for the hypercall result.
| 21 | `0x7FF93428DDBC` | `mov rax, [rcx+8]` | Loads source pointer (command buffer).
| 22 | `0x7FF93428DDC0` | `mov ecx, 0x90909090` | Command parameter sent to DBVM (hard-coded).
| 23 | `0x7FF93428DDC5` | `mov edx, 0x76543210` | Default DBVM password transmitted regardless of user changes.
| 24 | `0x7FF93428DDCA` | `vmmcall` | Executes hypervisor call on AMD-capable CPUs when predicate matched.
| 25 | `0x7FF93428DDCD` | `mov [r8], rax` | Stores return value into caller-provided buffer.
| 26 | `0x7FF93428DDD0` | `mov [rsp+8+var_4], 0x6EEFFA24` | Records response code for later validation.
| 27 | `0x7FF93428DDD8` | `mov eax, [rsp+8+var_4]` | Moves response into EAX for return.
| 28 | `0x7FF93428DDDC` | `jmp 0x7FF93428DE23` | Skips the `vmcall` path when `vmmcall` executed.

The alternate path at `0x7FF93428DDDE` uses the same parameter values but issues `vmcall` for Intel CPUs. In both branches the default password (`0x76543210`) and command (`0x90909090`) are hard-coded, so changing DBVM passwords alone does not prevent detection.

### 42.2 Response Validation
- After the hypercall returns, `sub_7FF93428D910` calls `sub_7FF93422B8A0` and checks whether `BYTE3(v5) << 24` equals `0xCE000000` (DBVM’s version signature). A match triggers `sub_7FF934371A80(19, 3, 2, 0, 0)` to log the detection event.
- The constants `0xCF5597E7`, `0x6EEC9A24`, and `0x6EEFFA24` serve as stage markers around the hypercall to keep stack state consistent with the surrounding anti-tamper logic.

### 42.3 Relationship to TLS Crash Paths
- The pointer sentinels visited before the hypercall reuse the same constants as the TLS callback. Any mismatch routes execution through the exact same crash loop (`0x7FF9343103B3`).
- Consequently, even this hypercall detector ultimately relies on the TLS infrastructure for termination: a detected DBVM instance either matches the version signature (leading to higher-level logging and eventual kill) or violates pointer expectations (immediate crash loop).

### 42.4 Practical Implications
- Roblox Hyperion always transmits the default DBVM credential pair `(0x90909090, 0x76543210)`. If DBVM has been recompiled with different passwords, Hyperion still issues the old combination and expects a valid response; failure to recognize the request will yield a mismatch result (`v5`) that the code treats as “not DBVM”.
- However, even if the hypercall does not return a DBVM signature, the surrounding pointer checks and TLS sentinels remain active; stealth modifications must also satisfy those comparisons to avoid termination.
## 43. Additional DBVM-Specific Constants and Pointer Guards in the Hypercall Path
During extended scanning of `dump.bin`, only two 32-bit constants matching the legacy DBVM credential pair are present inside the hypercall function cluster (`sub_7FF93428D910` / `sub_7FF93428DD70`):
- `0x76543210` (default DBVM password) at `0x7FF93428DDC6` and `0x7FF93428DE0A`.
- `0x90909090` (command parameter) immediately preceding both the `vmmcall` and `vmcall` instructions (`0x7FF93428DDC0`, `0x7FF93428DE04`).

No alternate password or signature constants (e.g., `0xA7B9C2E4`, `0x9F3E7A5B`, `0x2C4D8E1A`) exist inside the module; brute-force scans returned zero hits. The hypercall packet header `0xFEDCBA980000000C` is stored as a 64-bit literal at `0x7FF93428DA58` immediately before the call to `sub_7FF9343718F0`.

### 43.1 Pointer Sentinels Unique to This Path
`sub_7FF93428D910` executes a pre-flight sequence of pointer validations distinct from the TLS loop. Any failure routes execution through the same crash scaffolds recorded earlier.

| Instruction Address | Description | Constant |
| --- | --- | --- |
| `0x7FF93428D95C` | Compare TEB byte vs table entry | `0xA228CC6A92972CC3` |
| `0x7FF93428D9EF` | Mask `NtCurrentPeb()->ProcessHeap` | `0xE2CA6A0B4A680495` & `0xA228CC6ACA5F3733` |
| `0x7FF93428DA26` | Mask `(TEB & PEB->Ldr)` | `0xA228CC6A4443C895` |
| `0x7FF93428DAB7` | Direct compare `PEB->ProcessHeap` | `0xA228CC6A3842863B` |
| `0x7FF93428DB10` | Mask `(TEB & PEB->Ldr)` post-call | `0xA228CC6A5DDE6003` |

These constants were added to the sentinel summary in Section 16. The dual path (AMD `vmmcall`, Intel `vmcall`) ensures the detector communicates with DBVM on either vendor platform while keeping the same credentials and packet structure.

### 43.2 Control Flow Recap
1. Precondition: pointer masks and TEB/PEB checks must match the encoded constants above. Any discrepancy falls back into crash loop `0x7FF9343103B3`.
2. Hypercall packet (`0xFEDCBA980000000C`) is initialised, and the handler chooses between `vmmcall` and `vmcall` depending on the obfuscated byte test.
3. The return value is stored via `mov [r8], rax`; Stage 1 then executes `sub_7FF93422B8A0` and compares `BYTE3(v5)` against `0xCE` to confirm DBVM’s version signature. Match ? Stage 2 instrumentation triggers. Mismatch ? control returns without raising detection, assuming pointer sentinels also passed.
4. Post-call pointer checks ensure DBVM did not tamper with loader structures mid-call.

With these findings, the module contains no alternative DBVM passwords or signatures beyond the standard pair and version check; detection relies on the combination of hard-coded credentials, response signature, and the pointer sentinels already catalogued.
## 44. Loader Integrity Routine (`sub_7FF934371A80`) – Additional Sentinel Constants
During a full decompilation pass on `sub_7FF934371A80` (invoked from the stage coordinator after the hypercall), several further sentinel constants and hashes surfaced. They extend the same detection model—every mismatch redirects into crash stubs or fail-fast exits. Key findings:

### 44.1 New `0xA228CC6A********` Pointer Guards
The routine checks a broader set of masked pointers and context structures:
- `0xA228CC6A31928AA7` – expected value for `NtCurrentPeb()->Ldr` in certain sub-branches.
- `0xA228CC6A50233B81` – guard value compared against `TEB->Win32ClientInfo[29]`.
- `0xA228CC6A6413A113` – sentinel for raw `TEB` pointer when processing loader callbacks.
- `0xA228CC6A7EA3E5CF` – mask applied to the saved return address before completing the routine.
- `0xA228CC6A9F9DFF8D` – additional check on `ProcessHeap` while walking `InLoadOrderModuleList`.
- `0xA228CC6AC859FE0B` and `0xA228CC6AC8E94861` – values used to validate the TLS expansion bitmap before invoking `sub_7FF934376150`.

All of these join the existing sentinel list; they have been appended to Section?16 for completeness.

### 44.2 Loader Hashes and Magic Constants
`sub_7FF934371A80` walks the loader’s `InLoadOrderModuleList` and builds a rolling hash using `0x800000001CB` multipliers, then compares it against two hard-coded 64-bit constants:
- `0xCC2E3E7085C6AC01` – expected checksum for the module name array.
- `0x14CA02A585913835` – expected hash for an export name processed through the same multiplier.

Any deviation from these reference values triggers the crash scaffold beginning at `0x7FF9343755A9` (numerous `*(_DWORD *)v63 = v63` stores leading to the same poison addresses used elsewhere).

### 44.3 Function-Hash Engines
The function uses several hash/validation macros (all obfuscated through `_security_cookie`):
- `0x80000000239` multipliers combined with rotated XORs to hash characters while verifying export names.
- Additional arithmetic sequences producing constants such as `0x14CE44ABDE010E3D`, `0xF889402F555BE8C9`, etc. These originate from the same AES-like tables deployed in the TLS decode routine.

### 44.4 Win32 and System Call Validation
`sub_7FF934371A80` also:
- Registers additional instrumentation callbacks using `sub_7FF93417CDC0`, `sub_7FF9341B7810`, and `sub_7FF9342587B0` (all fed with the decoded table values above).
- Verifies multiple system calls succeed; failure cases call the crash scaffold or `invalid_parameter_noinfo_noreturn`.
- Confirms the Process Instrumentation Callback pointer is active by hashing internal lists and invoking targeted thunks.

### 44.5 Crash-Fallback Observations
The routine contains the same templated crash loop seen in TLS, with repeated writes to poison addresses:
```
MEMORY[0x9D95AFCCB5AF6946] = ...
MEMORY[0x9D95AFCCB51D6943] = ...
MEMORY[0xCCCCCCCCCCCCCCCC] = ...
```
These appear if any loader hash, pointer sentinel, or Win32 guard fails.

All new constants and behaviours are now recorded in the manual. While they do not introduce alternative DBVM credentials, they underscore how Hyperion combines loader integrity, hash verification, and context hashing to maintain control even after the hypercall stage.
