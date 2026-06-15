# Hercule v2.0 — Advanced Ransomware Behaviour Simulator (AES-256-CBC)

Hercules v2.0 is an advanced, high-performance storage simulation utility designed to replicate aggressive, direct-to-disk write streams. Moving beyond the staging mechanics of v1.0, this iteration focuses strictly on **In-Place Sector Overwriting**, providing a rigorous benchmark engine to validate the real-time blocking response, synchronization primitives, and IRQL safety of kernel-mode security filters.

This utility was specifically engineered to stress-test the `PreWrite` behavioral analytics engine of the [Kratos Anti-Ransomware Minifilter](https://github.com/mukendi/kratosminifilter).

---
