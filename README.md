<h1 align="center"> VENEX C2 v0.5 — (Test Version) </h1>

<div align="center"> <img width="300" height="300" alt="venex-modified" src="https://github.com/user-attachments/assets/be2ec9ea-fac7-4896-896b-b75fcb38ce31" /> </div>
<br>

> **Warning:** This is an early/test release. Use only in controlled lab environments/Ctfs. Linux gost is currently available with limited stealth features. **Not for production use.**

## Overview

**Venex** is a C2 framework (v0.5) for creating and managing modules, shellcode, and encrypted payloads. It supports team collaboration using a server–client architecture. This early release provides a minimal toolset for building, obfuscating, and distributing small payload modules. Some functionality is intentionally limited while the project is under development.

**Installation Guide:** For full installation steps, see [Installation Guide](docs/INSTALL.md).

## Quick facts
* Attack Vector: Windows (C2 server and tools run on Windows; client is Python-based and cross-platform. Linux support come in future updates)
* Target: Linux x86_64 (core, dropper, loader currently for Linux)
* Module size limit: **< 512 bytes** (1024 is posible but recomended under 512)
* Encryption: ChaCha20 (used by `encrypt.exe`)
* API table driven modules: functions are called via an API table pointer in `rax`.

## Repository structure

```
/C2Client     # Python client: connects to server and maintains targets
/tools/       # Main tooling for building/encrypting/obfuscating payloads
/gostinit     # Core malware dropper/loader for Linux_x64 (limited stealth)
/mosules      # Default modules (small shell access modules, helpers, etc.)
/server/      # Server: handles clients and target bridging
```

> Note: The server and victim use encrypted connection server will encrypt modules automaticaly (for example: an encrypted 74-byte msfvenom reverse shell). This example is for testing only and msf tcp reverse shell not production-safe.

## Tools

| Tool             | Description                       | Notes                                                               |
| ---------------- | --------------------------------- | ------------------------------------------------------------------- |
| `encrypt.exe`    | Encrypt / decrypt data (ChaCha20) | Used to secure modules and communications                           |
| `obfuscater.exe` | Obfuscate data                    | Obfuscates core shellcode/gosts before delivery                     |
| `hash.exe`       | Generate syscall hashes           | Generates hashes for syscall numbers used by gost shellcode         |
| `gostmsf.exe`    | Shellcode engine / builder        | Intended to build a full project in one step (not included in v0.5) |

## Creating modules (size < 512 bytes)

* Modules are designed to be very small. This version imposes a 512-byte size limit.
* Each exported function inside a module has an RVA (Relative Virtual Address).
* The runtime computes the function address as:

```
function_address = base + func_RVA
```

### API table

The loader populates an API table and places a pointer to it in `rax` before calling module code. Module writers should use this table to call host-provided helper functions.

| Index | Name             | Description                                    |
| ----- | ---------------- | ---------------------------------------------- |
| 0     | `base`           | Base address used to compute `base + func_RVA` |
| 1     | `gostEncrypt`    | Encrypt data                                   |
| 2     | `gostExecute`    | Execute a binary                               |
| 3     | `gostGetSyscall` | Resolve a syscall number by hash               |
| 4     | `gostEXESyscall` | Perform a raw syscall (shim)                   |
| 5     | `gostPrint`      | Print to client (encrypted)                    |
| 6     | `gostSend`       | Send data to client (alias of `gostPrint`)     |

### Calling a function from the API table (example, NASM-style)

The core places a pointer to the API table in `rax` when module start executing. To call an API function, load the function pointer, add the base, and call it.

```nasm
; rax -> pointer to API table
; To call API index N:
mov rbp, [rax + N*8]   ; load function RVA/pointer from table
add rbp, [rax]         ; add base (stored at API index 0)
call rbp               ; call final function address
```

> Note: The exact layout may vary by core version; confirm the binary's API table layout before building modules.

## Development notes

* Keep modules small and focused (single-responsibility). Large functionality should be split across multiple modules.
* Test modules thoroughly in a sandbox or isolated network before any remote execution.
* Use `hash.exe` to compute syscall hashes consistently across builds.
* `gostmsf.exe` will eventually provide an opinionated build flow to combine obfuscation + encryption + module packaging in one step.

## System Requirements

* **Attack Vector (C2 Infrastructure)**:
  - **C2 Server**: Runs on Windows (`server.exe` in `/server`).
  - **Tools**: `encrypt.exe`, `obfuscater.exe`, and `hash.exe` in `/tools` are Windows executables.
  - **Client**: Python-based (`/C2Client`), cross-platform (Windows, Linux, macOS with Python 3).
* **Target (Malware)**:
  - **Operating System**: Linux x86_64.
  - **Components**: `gostinit` (dropper/loader) and modules (e.g., `x.bin`) are built for Linux.
* **Build Environment**:
  - Windows: For building tools and server (using `make` with MinGW/MSYS or compatible).
  - Linux: Required for linking `gostinit` loader (ELF binary).

## Security & Ethics

This project contains offensive security tooling. Only use Venex within environments where you have explicit permission to test (your own lab, employer-sponsored test networks, or explicit client authorization). Unauthorized use against third parties is illegal and unethical.

<!-- ## Contributing

If you want to contribute:

1. Fork the repo.
2. Create a feature branch.
3. Submit a pull request with a clear description and tests (where applicable).

Please avoid submitting payloads or tooling that would enable uncontrolled distribution or abuse. -->

<!-- ## Roadmap (short)

* Improve Linux loader stealth and reliability
* Add Windows gost support (planned)
* Complete `gostmsf.exe` integration for streamlined builds
* Add automated testing for module boundaries and API compatibility -->

## License & Contact

Not yet licensed — project is still in development. Public forks are allowed on GitHub.


