global _syscallExtracter
global _stubExtracter
section .text
;function to extract syscalls using hell's gate input is eax
_syscallExtracter:
    pop rbp
    push rcx 
    push rdx
    push r8 
    push r9
    mov r10d,eax
    xor rdx,rdx
    mov rdx,[gs:rdx+0x60]
    mov rdx,[rdx+0x18]
    mov rdx,[rdx+0x20]
getModulName:
    mov rsi,[rdx+0x50] ;ntdll.dll
    movzx rcx,word [rdx+0x4a]
    call _hash_unicode
    cmp r9d,0x2bc46ff9 ; hash of "ntdll.dll"
    jz getfuncName
    mov rdx,[rdx]
    jmp getModulName

getfuncName:
    push rdx ;push base of modul
    push r9 ;push ntdll.dll hash value to stack
    mov rdx,[rdx+0x20]
    mov eax,[rdx+0x3c]
    add rax,rdx
    mov eax,[rax+0x88]
    test rax,rax
    add rax,rdx
    push rax
    mov ecx,[rax+0x18]
    mov r8d,[rax+0x20]
    add r8,rdx
extract_loop:
    jrcxz end_extract
    dec rcx
    mov esi,[r8+rcx*4]
    add rsi,rdx
    call _hash_ascci
    add r9,[rsp+8]
    cmp r9d,r10d
    jnz extract_loop
    pop rax
    mov r8d,[rax+0x24]
    add r8,rdx
    mov cx,[r8+rcx*2]
    mov r8d,[rax+0x1c]
    add r8,rdx
    mov eax,[r8+rcx*4]
    add rax,rdx
    mov ebx,[rax]
    cmp ebx,0xb8d18b4c
    jnz end_extract
    mov eax,[rax+4]
    ;syscall

end_extract:
    pop r10
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    jmp rbp
    

;this is hash function
;=========================
_hash_unicode:
    xor r9, r9
    xor rbx, rbx
    xor rax,rax
loop1:
    lodsb
    cmp al,0x61
    jl lawercase1
    sub al,0x20
lawercase1:
    mov bl, al
    add al, al
    xor al, bl   
    add r9d, eax
    push rcx
    mov cl,bl
    ror r9d, cl     
    pop rcx
    loop loop1
    ret
;==========================
;this is hash function
;=========================
_hash_ascci:
    push rcx
    xor r9, r9
    xor rbx, rbx
    xor rax,rax
loop2:
    lodsb
    cmp al,0x61
    jl lawercase2
    sub al,0x20
lawercase2:
    mov bl, al
    add al, al
    xor al, bl   
    add r9d, eax
    mov cl,bl
    ror r9d, cl
    test bl,bl
    jnz loop2
    pop rcx
    ret
;==========================





;=================================InderectSyscall
_stubExtracter:
    pop rbp
    push rax
    push rcx
    push rdx
    push r8 
    push r9
    mov r10d,eax
    xor rdx,rdx
    mov rdx,[gs:rdx+0x60]
    mov rdx,[rdx+0x18]
    mov rdx,[rdx+0x20]
getModulName1:
    mov rsi,[rdx+0x50] ;ntdll.dll
    movzx rcx,word [rdx+0x4a]
    call _hash_unicode
    cmp r9d,0x2bc46ff9 ; hash of "ntdll.dll"
    jz getfuncName1
    mov rdx,[rdx]
    jmp getModulName1

getfuncName1:
    ;push rdx ;push base of modul
    ;push r9 ;push ntdll.dll hash value to stack
    mov rdx,[rdx+0x20]
    mov eax,[rdx+0x3c] ;PE header
    add rax,rdx
    mov eax,[rax+0x88] ;export table adress
    test rax,rax
    add rax,rdx ;export table VA
    mov r8d,[rax+0x1c] ;adressOfFunctions
    add r8,rdx
    ;push r8 ;save function adress array

    mov eax,[r8+4*280]
    add rax,rdx ;VA of function
    mov rcx,50
stub_extract_loop:
    mov r10w,[rax]
    cmp r10w,0x050f
    jz dosyscall
    inc rax
    dec rcx
    jnz stub_extract_loop

exit:
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    jmp rbp

dosyscall:
    mov r11,rax
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    mov r10,rcx
    call r11
    jmp rbp

