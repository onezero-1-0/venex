
%macro NIBBLES 1-*
    %rep %0/2
        ; high nibble = next argument
        %define hi %1
        %rotate 1
        
        ; low nibble = next argument
        %define lo %1
        %rotate 1

        db (hi << 4) | lo
    %endrep

    ; If odd number of nibbles → store last nibble in high half
    %if %0 % 2
        db (%1 << 4)
    %endif
%endmacro


section .data
    array_pointers:
        compressed  dq 1
        uneque      dq 1
        base        dq 2


    ; #covert base 10 in to a another base that can represent as XX (eg: 11 22 55 AA) and return result and base
    ; # def to_base(n):
    ; #     y = n
    ; #     if n < 3:
    ; #         return f"{n}{n}",10
        
    ; #     for base in range(2,37):
    ; #         digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ; #         result = ""
    ; #         while n > 0:
    ; #             n, r = divmod(n, base)
    ; #             result = digits[r] + result
    ; #         n = y
    ; #         if(len(result) != 2):
    ; #             continue
    ; #         if(result[0] == result[1]):
    ; #             return result,base
        
    ; #     return "11",n-1

    ; NOTE ABOUT THE LOOKUP TABLE

    ; The lookup table used here is *not* arbitrary or random.
    ; Every entry is actually derived from a deterministic rule:

    ;     Each byte value (0–255) is converted into a number system
    ;     (base 2–36) where the value can be represented using exactly
    ;     two repeated digits — for example: "11", "22", "AA", "FF", etc.

    ;     Example:
    ;         10 (decimal) = "11" in base 9
    ;         because 1×9 + 1 = 10.

    ; This means the entire table can be generated programmatically
    ; at runtime, and does not need to be stored explicitly in memory.
    ; A function can be written to compute the two-digit repeated-symbol
    ; representation for each byte on demand, instead of referencing a
    ; hard-coded 256-entry lookup table.

    my_bytes db 12, 15, 200, 33, 7, 89, 150, 255, 0, 67
          db 23, 98, 134, 76, 190, 5, 15, 11, 99, 44
          db 88, 172, 15, 15, 1, 17, 83, 15, 59, 38
          db 15, 215, 73, 15, 9, 31, 128, 15, 187, 54
          db 222, 2, 121, 199, 15, 69, 175, 81, 230, 3

    ;10, 10, 10
    ;0, 10, 11
    ;0, 1, 2 for number < 3 are fake values

    base_array db 10, 10, 10, 2, 3, 4, 5, 6, 3, 8, 4, 10, 5, 12, 6, 4, 15, 16, 5, 18, 19, 6, 10, 22, 5, 24, 12, 8, 6, 28, 14, 30, 15, 10, 16, 6, 8, 36, 18, 12, 19, 40, 13, 42, 10, 8, 22, 46, 15, 48, 24, 16, 12, 52, 8, 10, 13, 18, 28, 58, 14, 60, 30, 8, 15, 12, 10, 66, 16, 22, 13, 70, 17, 72, 36, 14, 18, 10, 12, 78, 15, 26, 81, 82, 13, 16, 85, 28, 10, 88, 14, 12, 22, 30, 93, 18, 15, 96, 13, 10, 19, 100, 16, 102, 12, 14, 105, 106, 17, 108, 21, 36, 13, 112, 18, 22, 28, 12, 117, 16, 14, 120, 121, 122, 30, 24, 13, 126, 15, 128, 12, 130, 21, 18, 133, 14, 16, 136, 22, 138, 13, 140, 141, 12, 15, 28, 145, 20, 36, 148, 14, 150, 18, 16, 13, 30, 25, 156, 157, 158, 15, 22, 17, 162, 163, 14, 165, 166, 13, 168, 16, 18, 171, 172, 28, 24, 15, 176, 177, 178, 14, 180, 25, 182, 22, 36, 30, 16, 187, 20, 18, 190, 15, 192, 193, 14, 27, 196, 17, 198, 19, 200, 201, 28, 16, 204, 205, 22, 15, 18, 20, 210, 211, 212, 213, 214, 17, 30, 217, 218, 19, 16, 36, 222, 15, 24, 225, 226, 18, 228, 22, 20, 28, 232, 17, 234, 235, 236, 16, 238, 19, 240, 21, 26, 243, 34, 245, 18, 30, 248, 24, 250, 17, 22, 253, 16
    result_arry:
        NIBBLES 0, 10, 11, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 2, 3, 1, 1, 3, 1, 1, 3, 2, 1, 4, 1, 2, 3, 4, 1, 2, 1, 2, 3, 2, 5, 4, 1, 2, 3, 2, 1, 3, 1, 4, 5, 2, 1, 3, 1, 2, 3, 4, 1, 6, 5, 4, 3, 2, 1, 4, 1, 2, 7, 4, 5, 6, 1, 4, 3, 5, 1, 4, 1, 2, 5, 4, 7, 6, 1, 5, 3, 1, 1, 6, 5, 1, 3, 8, 1, 6, 7, 4, 3, 1, 5, 6, 1, 7, 9, 5, 1, 6, 1, 8, 7, 1, 1, 6, 1, 5, 3, 8, 1, 6, 5, 4, 9, 1, 7, 8, 1, 1, 1, 4, 5, 9, 1, 8, 1, 10, 1, 6, 7, 1, 9, 8, 1, 6, 1, 10, 1, 1, 11, 9, 5, 1, 7, 4, 1, 10, 1, 8, 9, 11, 5, 6, 1, 1, 1, 10, 7, 9, 1, 1, 11, 1, 1, 12, 1, 10, 9, 1, 1, 6, 7, 11, 1, 1, 1, 12, 1, 7, 1, 8, 5, 6, 11, 1, 9, 10, 1, 12, 1, 1, 13, 7, 1, 11, 1, 10, 1, 1, 7, 12, 1, 1, 9, 13, 11, 10, 1, 1, 1, 1, 1, 12, 7, 1, 1, 11, 13, 6, 1, 14, 9, 1, 1, 12, 1, 10, 11, 8, 1, 13, 1, 1, 1, 14, 1, 12, 1, 11, 9, 1, 7, 1, 13, 8, 1, 10, 1, 14, 11, 1, 15

section .bss
    obfuscated_buffer resb 8


section .text
global nibbleBaseObfuscate
global nibbleBaseDeObfuscate

nibbleBaseObfuscate:
    push rbp
    mov rbp,rsp
    cld

    mov [rel obfuscated_buffer],rsi
    mov rsi,rdi

    sub rsp,50
    mov r10,rsp ; storing result buffer
    mov [rel compressed],r10

    sub rsp,50
    mov r9,rsp ; storing base buffer
    mov [rel base],r9
    
    ;lea rsi, [rel _start]; rsi input adress

    push r10
    push r9

    xor rbx,rbx
    mov rcx,25
base_conver_loop:
    lodsb
    call to_base
    mov [r9],al ;store base
    mov bl,dl ;store result
    shl bl,4

    inc r9

    lodsb
    call to_base
    mov [r9],al ;store base
    or dl,bl
    mov [r10],dl ;store result

    inc r9
    inc r10
    loop base_conver_loop

    pop r9
    pop r10

    mov rsi,r9
    mov rcx,50

    sub rsp,50
    mov r11,rsp
    mov rdi,r11
    mov [rel uneque],rdi
    call remove_duplicates

    ;rdi we have uneque one
    ;rsi we have base one
    ;rcx unque length
    push rcx

    mov rax,rsi
    mov rsi,rdi
    mov rdi,rax
    cmp rcx,16
    jg byte_mapping

    call nibble_index_mapper
    xor rax,rax ;byte_maping = false
    mov ah,25
    jmp x1

byte_mapping:
    call byte_index_mapper
    mov rax,1 ;byte_maping = true
    mov ah,50


x1:

    pop rcx

    ; rcx unque length
    ; rdi base array
    ; rsi uneque
    push rcx

    mov rdi, [rel obfuscated_buffer]
    mov [rdi],al
    inc rdi
    mov [rdi],cl
    inc rdi
    ; mov byte [rdi],50
    ; inc rdi

    ;4byte padding
    ; xor rbx,rbx
    ; mov [rdi],ebx
    ; add rdi,4

    ;coppy uneque array in to obfuscated_buffer
    ; rcx unque length
    ; rsi uneque
    ; rdi obfuscated_buffer
    rep movsb

    ;4byte padding
    ; xor rbx,rbx
    ; mov [rdi],ebx
    ; add rdi,4

    ;copy compressed/result array in to obfuscated_buffer
    mov rsi,[rel compressed]
    mov rcx,25
    rep movsb

    ;copy base/mapped_base array in to obfuscated_buffer
    mov rsi,[rel base]
    shr rax,8
    and rax,0xFF
    mov rcx,rax
    rep movsb

    ;4byte padding
    xor rbx,rbx
    mov [rdi],ebx
    add rdi,4

    pop rcx
    add rcx,64 ;full size with padding / without padding size is full size - 12 (Ex: oringinel size alway 50 chunk after size 74 mean actualy 62)

    leave
    ret



nibbleBaseDeObfuscate:

    push rbp
    mov rbp,rsp

    mov rsi,rcx
    mov r8,rdx

    ;rsi
    xor rcx,rcx

    mov al,[rsi]
    inc rsi
    mov cl,[rsi] ;size of unuque
    inc rsi

    test al,al
    jnz halfnibble

fullnibble:
    ;add rcx,25+25+2 ;rcx alrady have unequer size then add result nibble size + base nible size + 2 (first header bytes)
    mov rdi,rsi
    add rdi,rcx
    add rdi,25
    push rdi
    call nibble_value_mapper

    mov rsi,rdi
    pop rdi
    sub rdi,25
    
    jmp fullANDhalf_nibble

    
halfnibble:
    ;add rcx,25+50+2 ;rcx alrady have unequer size then add result nibble size + base byte size + 2 (first header bytes)

    ;mov rsi,unuqeu_array
    ;mov rcx,size
    mov rdi,rsi
    add rdi,rcx
    add rdi,25
    call byte_value_mapper
    mov rsi,rdi
    sub rdi,25

fullANDhalf_nibble:
    ; mov rsi,rdi
    ; sub rdi,25

    mov rcx,25

    nibble_loop:
        lodsb
        mov bl,al

        mov r10b,[rdi]
        and r10b,0xF0
        shr r10b,4
        call from_base_value
        mov [r8],al

        inc r8

        lodsb
        mov bl,al

        mov r10b,[rdi]
        and r10b,0x0F
        call from_base_value
        mov [r8],al

        inc r8
        inc rdi
        loop nibble_loop

    leave
    ret






to_base:
    and rax,0x00000000000000FF
    push rbx              ; save callee-saved
    push r9
    push r12              ; we need two scratch registers
    push r13
    push rcx

    mov r12, rax          ; save input number

    lea r13, [rel base_array]
    lea rbx, [rel result_arry]

    add r13, rax
    mov al, [r13]         ; load base value
    mov r9, rax           ; save base

    ; r12 = input number (0..255)
    xor rdx, rdx
    mov rax, r12
    mov rcx, 2
    div rcx               ; rax = index, rdx = remainder

    test rdx, rdx
    jnz .lower

.higher:
    add rbx, rax
    mov dl, [rbx]
    and dl, 0xF0
    shr dl, 4
    mov rax, r9           ; return base in rcx
    jmp .done

.lower:
    add rbx, rax
    mov dl, [rbx]
    and dl, 0x0F
    mov rax, r9           ; return base in rcx

.done:
    pop rcx
    pop r13
    pop r12
    pop r9
    pop rbx
    ret



;rsi input array, rcx in/out size, rdi output array ;r9,r10,rax,rbx
remove_duplicates:
    push rax
    push rbx
    push r9
    push r10
    push r11
    push rsi

    xor r9,r9 ;int count = 0;

    input_loop:       ;for (int i = 0; i < n; i++)
        cmp rcx,0
        jz return

        xor r11,r11   ;seen = 0

        xor r10,r10   ;j = 0

        lodsb         ;arr[i]

        checker:      ;for (int j = 0; j < count; j++)
            
            cmp r10,r9
            jnl add_output

            mov bl,[rdi+r10]
            inc r10

            cmp al,bl ;out[j] == arr[i]
            jz break
            jmp checker
        
        add_output:   ;if (!seen)
            cmp r11,0
            jnz break
            mov [rdi+r9],al
            inc r9

        break:
            dec rcx
            jmp input_loop

    return:
        mov rcx,r9

        pop rsi
        pop r11
        pop r10
        pop r9
        pop rbx
        pop rax
        ret



;mov rsi,unuqeu_array
;mov rcx,12
;mov rdi,base_array

nibble_index_mapper:
    push rax
    push rbx
    push rdx
    push rsi
    push rdi

    xor rax,rax
    sub rsp,256

    xor rbx,rbx            ; i = 0
    fill_lookup:
        test rcx,rcx
        jz map

        lodsb
        mov [rsp + rax],bl   ;value : index
        inc rbx
        dec rcx
        jmp fill_lookup
    
    map:
        mov rcx,0
        mov rsi,rdi
    map_in_place:              
        lodsb
        mov bl, [rsp + rax]
        and bl,0x0F
        shl bl,4

        lodsb
        mov dl, [rsp + rax]
        and dl,0x0F

        or bl,dl

        neg rcx
        mov [rsi + rcx - 2],bl
        neg rcx

        inc rcx
        cmp rcx,25
        jnz map_in_place
    
    add rsp,256

    pop rdi
    pop rsi
    pop rdx
    pop rbx
    pop rax
    ret



;mov rsi,unuqeu_array
;mov rcx,12
;mov rdi,base_array

byte_index_mapper:
    push rax
    push rbx
    push rdx
    push rsi
    push rdi

    xor rax,rax
    sub rsp,256

    xor rbx,rbx            ; i = 0
    fill_lookupb:
        test rcx,rcx
        jz mapb

        lodsb
        mov [rsp + rax],bl
        inc rbx
        dec rcx
        jmp fill_lookupb   ;value : index
    
    mapb:
        mov rcx,0
        mov rsi,rdi
    map_in_placeb:         ;value : index
        lodsb
        mov bl, [rsp + rax]

        mov [rsi - 1],bl

        inc rcx
        cmp rcx,50
        jnz map_in_placeb
    
    add rsp,256

    pop rdi
    pop rsi
    pop rdx
    pop rbx
    pop rax
    ret


;bl base and r10b value   colab rsi rdi r8 r9 rdx rcx 
from_base_value:
    push rsi
    push rdi
    push r8
    push r9
    push rdx
    push rcx

    lea rsi, [rel base_array]
    lea rdi, [rel result_arry]
    ;mov rcx,50
    mov r8,rsi
base_loop:
    lodsb
    cmp al,bl
    jnz base_loop

    mov rax,rsi
    sub rax,r8 ;rax is index 5
    dec rax 

    mov r9,rax ;save index

    xor rdx, rdx
    mov rcx, 2
    div rcx               ; rax = index, rdx = remainder

    test rdx, rdx
    jnz .lower

.higher:
    mov dl, [rdi+rax]
    and dl, 0xF0
    shr dl, 4
    cmp dl,r10b
    jz .done
    jmp base_loop

.lower:
    mov dl, [rdi+rax]
    and dl, 0x0F
    cmp dl,r10b
    jz .done
    jmp base_loop

.done:
    mov rax, r9 ; return index in rcx

    pop rcx
    pop rdx
    pop r9
    pop r8
    pop rdi
    pop rsi
    ret


    


;mov rsi,unuqeu_array
;mov rcx,12
;mov rdi,base_array
byte_value_mapper:
    push rax
    push rbx
    push rdx
    push rsi
    push rdi

    xor rax,rax
    sub rsp,256

    xor rbx,rbx            ; i = 0
    value_fill_lookupb:
        test rcx,rcx
        jz value_mapb

        lodsb
        mov [rsp + rbx],al
        inc rbx
        dec rcx
        jmp value_fill_lookupb   ;index : value
    
    value_mapb:
        mov rcx,0
        mov rsi,rdi
    value_map_in_placeb:         ;value : index
        lodsb
        mov bl, [rsp + rax]

        mov [rsi - 1],bl

        inc rcx
        cmp rcx,50
        jnz value_map_in_placeb
    
    add rsp,256

    pop rdi
    pop rsi
    pop rdx
    pop rbx
    pop rax
    ret


;mov rsi,unuqeu_array
;mov rcx,12
;mov rdi,base_array
nibble_value_mapper:
    push rax
    push rbx
    push rdx
    push rsi
    push rdi

    xor rax,rax
    sub rsp,256

    xor rbx,rbx            ; i = 0
    nibble_value_fill_lookupb:
        test rcx,rcx
        jz nibble_value_mapb

        lodsb
        mov [rsp + rbx],al
        inc rbx
        dec rcx
        jmp nibble_value_fill_lookupb   ;index : value
    
    nibble_value_mapb:
        mov rcx,0
        mov rsi,rdi
        sub rsp,50
        mov rdx,rsp
        add rsp,50
    nibble_value_map_in_placeb:         ;value : index
        lodsb
        mov bl,al
        and al,0xF0
        shr al,4
        and bl,0x0F

        mov al, [rsp + rax]
        mov bl, [rsp + rbx]

        mov [rdx],al
        inc rdx
        mov [rdx],bl
        inc rdx
        

        inc rcx
        cmp rcx,25
        jnz nibble_value_map_in_placeb
    
    sub rdx,50
    add rsp,256

    pop rdi
    mov rdi,rdx
    pop rsi
    pop rdx
    pop rbx
    pop rax
    ret
