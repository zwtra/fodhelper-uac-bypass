global _call_proc

section .text

_call_proc:
    push ebp
    push esi
    push edi
    push ebx
    mov ebp, esp

    mov ecx, [ebp + 0x18]
    neg ecx

    lea esp, [esp + ecx * 0x4]
    neg ecx

    mov edi, esp
    mov esi, ebp
    add esi, 0x1c

    rep movsd

    call [ebp + 0x14]

    mov esp, ebp
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret
