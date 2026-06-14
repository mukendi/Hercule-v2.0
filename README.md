# Hercules v2.0: Advanced Low-Level In-Place I/O Stress-Testing Engine

Hercules v2.0 is an advanced, high-performance storage simulation utility designed to replicate aggressive, direct-to-disk write streams. Moving beyond the staging mechanics of v1.0, this iteration focuses strictly on **In-Place Sector Overwriting**, providing a rigorous benchmark engine to validate the real-time blocking response, synchronization primitives, and IRQL safety of kernel-mode security filters.

This utility was specifically engineered to stress-test the `PreWrite` behavioral analytics engine of the [Kratos Anti-Ransomware Minifilter](https://github.com/mukendi/kratosminifilter).

---

## 🔬 Simulation Mechanics (v2.0 Specifications)

Hercules v2.0 bypasses intermediate files entirely to simulate an aggressive, low-latency, and destructive data modification pattern:

1. **Direct Handle Acquisition:** Opens a direct read/write handle onto the targeted file object without creating temporary `.tmp` extensions.
2. **In-Place Sector Overwriting:** Executes rapid, successive `WriteFile` requests, mapping high-entropy streaming payloads directly over the existing sectors of the file.
3. **Resource Exhaustion Simulation:** Spawns asynchronous concurrent threads to maximize I/O requests per second (IOPS), explicitly designed to stress-test kernel lock architectures (such as `FAST_MUTEX` vs `SpinLocks` transitions in the intercepting driver).
4. **Dynamic Context Evading:** Alters write sequence chunk sizes mid-stream to challenge and evaluate static buffer sampling limitations.

---

## 🛡️ Hardcoded Safety Architecture

To ensure compliance with safety standards and prevent unauthorized execution, Hercules v2.0 maintains rigorous structural guardrails:

* **Volatile Sandbox Isolation:** The software utilizes a defensive directory verification subroutine. Execution is completely restricted to the designated lab environment (`C:\TestLab\`). Execution on root directories, network shares, or user profiles is blocked at the binary level.
* **Reversible Entropy Payloads:** **This software does not incorporate cryptographic algorithms (such as AES, RSA, or ChaCha20).** The high-entropy payload is synthetically generated via fixed, reproducible mathematical arrays designed to mimic the statistical density of encrypted data. This allows entropy filters to trigger naturally while ensuring data can be verified and reverted within the test lab.

---

## ⚠️ Strict Legal & Ethical Use Disclaimer

{% callout type="warning" title="Legal Notice" %}
Hercules v2.0 is an advanced testing tool that interfaces aggressively with system file handles. 

1. **Regulatory Compliance:** Execution of this utility must strictly comply with local authorization laws. Unauthorized use on computing systems without explicit written consent from the resource owner is illegal.
2. **Testing Limitations:** This tool is designed exclusively for closed-loop sandboxes and virtual machines. The author declines all responsibility for data loss, operating system crashes, or operational disruption caused by testing this tool.
3. **No Weaponization:** Modifying this source code to include real encryption, asymmetric key generation, or network command-and-control capabilities is a violation of the intended research use-case of this repository.
{% /callout %}

---

## 🛠️ Build & Deployment

1. Open `HerculesV2.sln` within Visual Studio 2022.
2. Set the active configuration profile to **Release / x64**.
3. Build the project to output the optimized native binary.
4. Ensure your isolated environment (`C:\TestLab\`) is populated with testing files.
5. Execute the binary from a command prompt running under administrative privileges.

---

**Author:** Simon Ngoy  
**Project Association:** Advanced Defensive Evaluation and Performance Validation for Project Kratos
