extern _syscallExtracter
extern _stubExtracter

global derectSleep

section .text

derectSleep:
    push rbp
	mov rbp,rsp
    push rbp
    ;rcx TRUE OR FALSE
    ;rdx seconds
    imul rdx, rdx, -10000000 

    sub rsp,40
    mov qword [rsp+16], rdx
    mov rcx,0
    lea rdx, [rsp+16]
    mov eax,0xB980B242
    call _syscallExtracter ;coloberd rbp
    call _stubExtracter ;coloberd rbp
    js error_handler
    mov rax,0
    jmp exit
    
error_handler:
    mov rax,-1

exit:
    add rsp,40
    pop rbp
    leave
    ret

