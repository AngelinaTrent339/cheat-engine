# DBVM Surfaces Analysis — Interfaces, Behaviors, Evidence, and Stable Anchors

This document analyzes the DBVM hypervisor (this repository’s `dbvm/vmm/*`) from the perspective of detection surfaces used by anti‑cheat probes (name/logo/memory checks previously mapped) and shows how DBVM is designed to resist them: handshake model, stealth suspend, CPUID handling, RDTSC, and error paths. It links directly to source files/lines in this repo for evidence and adds future‑proof signature anchors.

Scope
- Codebase: `dbvm/vmm` sources in this repository
- Not Windows Hyper‑V: DBVM is a custom bare‑metal hypervisor; it does not advertise hypervisor leaves and actively hides CPUID ECX[31] in untrusted contexts.


## 1) VMCall Interface and Password Handshake

Entry and flow
- Top‑level: handleVMCall → _handleVMCall → password check → map guest data → dispatch
  - `dbvm/vmm/vmcall.c:2661` (critical section + try/except wrapper) → `dbvm/vmm/vmcall.c:2499` (definition of `_handleVMCall`)

Passwords (Level‑1 + Level‑2)
- Register level‑1 (must match, else #UD):
  - Password1 in RDX, Password3 in RCX: `dbvm/vmm/vmcall.c:2540:2543` (compares, logs on mismatch)
- Structure level‑2 (header):
  - Password2 in vmcall_instruction[0] and size in [2]: `dbvm/vmm/vmcall.c:2579:2586` (validates, else `raiseInvalidOpcodeException`)
- Final mapping of guest structure when size > 12: `dbvm/vmm/vmcall.c:2608:2618`

Passwords initialization
- DBVM sets non‑default passwords at boot via XOR masks (no static constants in memory):
  - `dbvm/vmm/main.c:305:310` (Password1/2/3 set via XOR mask constants)

Stealth implications
- Wrong passwords and some invalid access paths deliberately raise #UD, indistinguishable from “no hypervisor present” unless you can side‑channel page faults vs #UD.


## 2) Stealth Suspend (No‑Hypervisor Simulation)

Goals
- When suspended with stealth enabled, block hypervisor visibility to untrusted userland.

Key functions and constants
- Status constants: `dbvm/vmm/suspend.h:6:9` (DBVM_STATUS_* values)
- Set/clear trusted CR3: `dbvm/vmm/suspend.c:39:60`, `dbvm/vmm/suspend.c:62:66`
- Authentication:
  - `suspend_authenticate_caller`: `dbvm/vmm/suspend.c:114:142` returns KERNEL / TRUSTED_CE / EXTERNAL
  - `suspend_is_trusted_context`: `dbvm/vmm/suspend.c:50:61`
- Decision to ignore vmcall: `suspend_should_ignore_vmcall`: `dbvm/vmm/suspend.c:184:199`
- Generate “no hypervisor present” exception: `suspend_generate_no_hypervisor_exception`: `dbvm/vmm/suspend.c:196:204` (calls `raiseInvalidOpcodeException`)

Where applied
- In `_handleVMCall`, before password check: `dbvm/vmm/vmcall.c:2643:2651`
  - If untrusted userland and stealth is enabled while suspended, DBVM injects #UD (no hypervisor) and returns.
- In AMD/Intel VM exit path around CPUID/VMCALL: `dbvm/vmm/vmeventhandler.c:4347:4355`, `dbvm/vmm/vmeventhandler_amd.c:1377:1378` (same policy when suspended)

Implication
- External probes (process scanners, logo checkers) will observe #UD on vmcall/vmmcall or VMX opcodes during stealth suspend.


## 3) CPUID Handling (Hiding Hypervisor Bit)

Handler
- `handleCPUID` in `dbvm/vmm/vmeventhandler.c:1924:2100`
  - Executes native `_cpuid` then applies policy.
  - If caller is not a trusted context and leaf EAX==1, clears ECX bit 31 (“hypervisor present”): `dbvm/vmm/vmeventhandler.c:1947:1952`

Notes
- There is no vendor‑signature advertising leaf (e.g., 0x40000000 family). The code does not craft custom hypervisor CPUID leaves.
- The old “brand string” spoof is commented out (evidence of historical testing), see `dbvm/vmm/vmeventhandler.c:1980:2008`.

Implication
- Anti‑cheat CPUID checks (hypervisor bit, vendor string) won’t see DBVM unless running in trusted context.


## 4) GETVERSION and Password‑Derived Signature

Dispatch case
- `VMCALL_GETVERSION` combines high byte from `(Password1 ^ Password3) & 0xff000000` with low 24‑bit `dbvmversion`:
  - `dbvm/vmm/vmcall.c:967:975` (case implementation), `dbvm/vmm/main.c:330` (`dbvmversion=16` in this tree)

Implication
- External version probes cannot rely on a fixed constant; the high byte changes with runtime passwords.


## 5) RDTSC and Timing Hooks

Variables and hooks
- Global flags and hooks: `dbvm/vmm/vmeventhandler.c` (top): `adjustTimestampCounters`, `TSCCS`, `useSpeedhack`, and `TSCHooked` (`dbvm/vmm/vmxsetup.c:36`, enabled in `:1502`)
- RDTSC handler: `int handle_rdtsc(...)` declaration at `dbvm/vmm/vmeventhandler.c:3977`; used in VM exit switch at `dbvm/vmm/vmeventhandler.c:4329` and `:4573`

Implication
- DBVM can adjust or hook TSC reads, mitigating timing probes that might be used to fingerprint hypervisors.


## 6) VMX Instruction Visibility Control

Policy
- If guest executes VMX instructions and context is not trusted while VMX is running, DBVM raises #UD to simulate lack of support:
  - `dbvm/vmm/vmeventhandler.c:4662:4671` (VMX ops case group) → `raiseInvalidOpcodeException`

Implication
- Userland probes executing VMX instructions will see #UD as if no hypervisor; avoids revealing presence.


## 7) Error Paths that Leak Signals (What to Watch)

- Wrong Passwords in VMCALL:
  - Level‑1 (registers) mismatch: raises #UD; logs in `dbvm/vmm/vmcall.c:2543`
  - Level‑2 (structure header/size) mismatch: raises #UD; logs in `dbvm/vmm/vmcall.c:2579:2594`
  - Over‑large structure (>16KB): raises #UD; `dbvm/vmm/vmcall.c:2601:2608`
- Unmapped vmcall data: may raise page fault via `raisePagefault`; `dbvm/vmm/vmcall.c:2631:2640`
- Suspended & stealth: `_handleVMCall` will not return success/err codes — it injects #UD; `dbvm/vmm/vmcall.c:2643:2651`

Detection risk
- Tools that differentiate between real #UD and synthetic (timing, IDT state) might identify DBVM vs a bare system; however, DBVM’s use of #UD is a common mimic‑strategy.


## 8) Future‑Proof Anchors for IDA Signatures

- VMCALL password check cluster:
  - `dbvm/vmm/vmcall.c:2540:2560` (RDX/RCX compare then `_handleVMCallInstruction` mapping)
  - `dbvm/vmm/vmcall.c:2579:2608` (Password2 + size checks + raiseInvalidOpcodeException)
- GETVERSION combine:
  - `dbvm/vmm/vmcall.c:967:975`
- Stealth suspend calls:
  - `dbvm/vmm/vmcall.c:2643:2651` and `dbvm/vmm/vmeventhandler.c:4347:4355`
- CPUID hypervisor‑bit masking:
  - `dbvm/vmm/vmeventhandler.c:1947:1952`
- VMX op #UD policy:
  - `dbvm/vmm/vmeventhandler.c:4662:4671`
- TSCHooked toggles:
  - `dbvm/vmm/vmxsetup.c:36`, `:1502`, `:1523`


## 9) What External Probes Will See

- CPUID: ECX[31] cleared for leaf 1 unless trusted → “no hypervisor”. No custom 0x4000xxxx leaves advertised.
- VMCALL: Wrong creds or external during stealth suspend → #UD (like no hypervisor).
- GETVERSION: A value whose high 8 bits depend on runtime passwords. No stable signature.
- VMX Instructions: #UD unless trusted.
- RDTSC: Potentially normalized; hard to fingerprint.


## 10) Suggested Anti‑Fingerprinting Hardening (if needed)

- Uniform #UD generation path for absent vs present‑but‑stealth to make timing identical.
- Optional randomized delay in wrong‑password #UD to blur low‑level timings.
- Keep password derivations per boot salted to avoid re‑use across restarts.


---

This mapping is grounded in the source and references line‑precise locations for verification. Combine these anchors with the SigMaker patterns already provided to set up resilient cross‑build identification of DBVM’s key behaviors.

