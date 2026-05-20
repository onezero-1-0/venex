<!-- <h1 align="center"> VENEX C2 v1.5 — (Test Version) </h1>

<div align="center"> <img width="300" height="300" alt="venex-modified" src="https://github.com/user-attachments/assets/be2ec9ea-fac7-4896-896b-b75fcb38ce31" /> </div>
<br>

> **Warning:** This is an early/test release. Use only in controlled lab environments/Ctfs. Windows gost is currently available with mid range stealth features. **Not for production use.**

## Overview

**Venex** is a C2 framework (v1.5) for creating and managing modules, shellcode, and encrypted payloads. It supports team collaboration using a server–client architecture. This early release provides a minimal toolset for building, obfuscating, and distributing small payload modules. Some functionality is intentionally limited while the project is under development.

**Installation Guide:** For full installation steps, see [Installation Guide](docs/INSTALL.md).

## Quick facts
* Attack Vector: Linux (C2 server and tools run on Linux; client is Python-based and cross-platform.)
* Target: Windows x86_64 (core, dropper, loader)
* Module size limit: **< 512 bytes** (1024 is posible but recomended under 512)
* Encryption: ChaCha20 (used by `encrypt.exe`)
* API table driven modules: functions are called via an ft structer.

## Repository structure

```
/C2Client     # Python client: connects to server and maintains targets
/tools/       # Main tooling for building/encrypting/obfuscating/hashing payloads
/gostinit     # Core malware dropper/loader for Win_x64 (limited stealth)
/mosules      # Default modules (small shell access modules, helpers, etc.)
/moduloScript # put multiple module togather
/server/      # Server: handles clients and target bridging
```

> Note: The server and victim use encrypted connection server will encrypt modules automaticaly

## Tools

| Tool             | Description                       | Notes                                                               |
| ---------------- | --------------------------------- | ------------------------------------------------------------------- |
| `encrypt.exe`    | Encrypt / decrypt data (ChaCha20) | Used to secure modules and communications                           |
| `windows_gost_tools/ntdllHashGenerator/hash.py` | Generate syscall hashes   | Generates hashes for syscall numbers used by gost shellcode 

limited tool are avilible for now

## Creating modules (size < 512 bytes)

to create a module you can use ft structer it has free defiend funtions and windows syscalls
for more detail go doc/createmodule.md


## moduloscript 

modulo script is way to run multiple command as once or reuse long command like alis you can put commands you want line by line

## Development notes

* Keep modules small and focused (single-responsibility). Large functionality should be split across multiple modules.
* Test modules thoroughly in a sandbox or isolated network before any remote execution.
* Use `hash.py` to compute syscall hashes consistently across builds.

## System Requirements

* **Attack Vector (C2 Infrastructure)**:
  - **C2 Server**: Runs on Linux (`server` in `/server/bin`).
  - **Tools**: `encrypt.exe`, and `hash.py` in `/tools` are Windows executables.
  - **Client**: Python-based (`/C2Client`), cross-platform (Windows, Linux, macOS with Python 3).
* **Target (Malware)**:
  - **Operating System**: Windows x86_64. (10/11 compotable)
  - **Components**: `gostinit` (dropper/loader) and modules (e.g., `tm.bin`) are built for Windows.
* **Build Environment**:
  - add it later

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
* Add automated testing for module boundaries and API compatibility 

## License & Contact

Not yet licensed — project is still in development. Public forks are allowed on GitHub.

 -->

<h1 align="center">VENEX C2 v1.5 — Test Version</h1>

<div align="center">
  <img width="300" height="300" alt="venex-modified" src="https://github.com/user-attachments/assets/be2ec9ea-fac7-4896-896b-b75fcb38ce31" />
</div>
<br>

> **Warning:** This is an early/test release. Use only in controlled lab environments / CTFs. Windows gost is currently available with mid-range stealth features. **Not for production use.**

---

## Overview

**Venex** is a C2 framework (v1.5) for creating and managing modules, shellcode, and encrypted payloads. It supports team collaboration using a server–client architecture. This early release provides a minimal toolset for building, obfuscating, and distributing small payload modules. Some functionality is intentionally limited while the project is under development.

**Installation Guide:** For full installation steps, see [Installation Guide](docs/INSTALL.md).

---

## Quick Facts

- **Attack Vector:** Linux (C2 server and tools run on Linux; client is Python-based and cross-platform)
- **Target:** Windows x86_64 (core, dropper, loader)
- **Module size limit:** **< 512 bytes** (1024 is possible but recommended under 512)
- **Encryption:** ChaCha20 (used by `encrypt.exe`)
- **API table driven modules:** Functions are called via an `ft` structure

---

## Repository Structure
/C2Client # Python client: connects to server and maintains targets
/tools/ # Main tooling for building/encrypting/obfuscating/hashing payloads
/gostinit # Core malware dropper/loader for Win_x64 (limited stealth)
/modules # Default modules
/moduloScript # Chain multiple modules together
/server/ # Server: handles clients and target bridging

> **Note:** The server and victim use encrypted connections. The server will encrypt modules automatically.

---

## Tools

| Tool | Description | Notes |
|------|-------------|-------|
| `encrypt.exe` | Encrypt / decrypt data (ChaCha20) | Used to secure modules and communications |
| `windows_gost_tools/ntdllHashGenerator/hash.py` | Generate syscall hashes | Generates hashes for syscall numbers used by gost shellcode |

*Limited tools are available for now.*

---

## Creating Modules (size < 512 bytes)

To create a module you can use the `ft` structure — it has free-defined functions and Windows syscalls.

For more details, see [docs/createmodule.md](docs/createmodule.md).

---

## ModuloScript

ModuloScript is a way to run multiple commands at once or reuse long commands like aliases. crate a .vms file in moduloScript folder and Put commands you want line by line. then use it name with $ as a command in client.(ex: - $myscript)

---

## Development Notes

- Keep modules small and focused (single-responsibility). Large functionality should be split across multiple modules.
- Test modules thoroughly in a sandbox or isolated network before any remote execution.
- Use `hash.py` to compute syscall hashes consistently across builds.

---

## System Requirements

**Attack Vector (C2 Infrastructure):**
- **C2 Server:** Runs on Linux (`server` in `/server/bin`)
- **Tools:** `encrypt.exe` and `hash.py` in `/tools` are Windows executables
- **Client:** Python-based (`/C2Client`), cross-platform (Windows, Linux, macOS with Python 3)

**Target (Malware):**
- **Operating System:** Windows x86_64 (10/11 compatible)
- **Components:** `gostinit` (dropper/loader) and modules (e.g., `tm.bin`) are built for Windows

**Build Environment:**
- *To be added later*

---

## Security & Ethics

This project contains offensive security tooling. Only use Venex within environments where you have explicit permission to test (your own lab, employer-sponsored test networks, or explicit client authorization). Unauthorized use against third parties is illegal and unethical.

---

## License & Contact

Not yet licensed — project is still in development. Public forks are allowed on GitHub.
