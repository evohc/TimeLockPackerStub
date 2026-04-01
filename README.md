
# TimeLockPackerStub

A Rust demo packer and loader that explores **Environmentally Keyed Execution**. It consists of a stub that acts as a reflective PE loader for in this case a Position Independent C (PIC) payload. The core twist here is that the decryption key for the payload is never stored in the binary. Instead, it is **generated at runtime** based on the CPU's execution timing, making the binary "difficult" for debuggers and emulators.

Note:
A **packer stub** is the self-extracting runtime engine of a protected executable. While the "packer" (or builder) is the external tool that encrypts and embeds the target payload into a new binary, the stub is the actual code that remains at the entry point of that new file. The packer never leaves the dev machine. When the packed program is executed, the stub runs first; its primary responsibilities are to manage the environment, derive or retrieve the decryption keys, and manually map the original payload’s sections into memory. 

### ### 1. The "Observer Effect" Anti-Analysis

The packer uses the CPU **Time Stamp Counter (TSC)** via `_rdtsc()` to measure the execution time of a specific workload loop.

-   **Normal Execution:** The loop runs in a predictable number of cycles (e.g., ~15 million).
    
-   **Debugged/Emulated Execution:** The overhead of context switching or instruction trapping by a debugger causes the cycle count to exponentially increase(e.g., >100 million).
    

The cycle count is divided into "buckets" to account for minor CPU variance. This bucket number _is_ the decryption key. If a debugger is present, the key is "destroyed" by the act of observation, resulting in a failed decryption of the `MZ` header and a silent exit.

### ### 2. Reflective Loading (Rust)

The stub includes a custom PE loader (`loader.rs`) that:

-   Allocates memory via `VirtualAlloc`.
    
-   Manually maps PE sections from the decrypted buffer.
    
-   Hand-rolls a `memcpy` to maintain `#![no_std]` compatibility without linking to the C runtime (CRT).
    
-   Jumps to the entry point of the C payload in memory.
    

### ### 3. Position Independent Payload (C)

The payload is written in raw C to ensure it has no external dependencies.  No absolute addresses, stack strings with relative addresses. This was generated using Gemini as its painful to write PIC code...and its takes time from learning Rust.
This was neccessary because base relocations and import resolution were too complex for a Rust learning project.  Base relocations would involves patching all the addresses to what VirtualAlloc returned.  Import Resolution requires fixing up the IAT table with the addresses of requisite functions e.g. user32::MessageBox.


## 📊 Detection & Variance

For a work loop of **25,000** iterations:

* **Normal Execution:** ~15,000,000 cycles.
* **Debugged Execution:** ~100,000,000+ cycles.

Because CPU cycles are never identical, we stabilize the variance using **Buckets**. By dividing the raw cycles by a factor (e.g., 500,000), we get a consistent key even with slight timing drifts:

| Trial | Raw CPU Cycles | Calculation | Final Bucket (Key) |
| :--- | :--- | :--- | :--- |
| **Run 1** | 15,000,102 | `/ 500,000` | **30** |
| **Run 2** | 15,000,450 | `/ 500,000` | **30** |
| **Run 3** | 15,000,970 | `/ 500,000` | **30** |

### Key Verification

The stub attempts to decrypt the first two bytes of the payload using a small range of buckets ($Bucket \pm 2$). If the decrypted bytes match the `MZ` (0x5A4D) signature, the key is confirmed and the full payload is decrypted.

> **Security Note:** While this potentially complicates automated sandbox analysis, a human researcher could extract the payload and brute-force the valid bucket in seconds. This is a demonstration of temporal evasion, not some unbreakable encryption.
