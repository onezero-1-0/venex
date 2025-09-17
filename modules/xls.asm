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
    push rax
    lea r10,[rel binls]
    xor r13,r13
    lea r14,[rel buf]
    mov rbp,[rax + 2*8]
    add rbp,[rax]
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

binls db "/bin/ls",0
pipefd dq 0
buf: times 460 db 0
