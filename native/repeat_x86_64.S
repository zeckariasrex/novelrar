/* System V AMD64 ABI: rdi=destination, rsi=distance, rdx=length.
 * Forward byte copies intentionally propagate overlapping LZ matches.
 */
.text
.globl nr_repeat_asm
.type nr_repeat_asm,@function
nr_repeat_asm:
    movq %rdi, %rax
    subq %rsi, %rax
    movq %rax, %rsi
    movq %rdx, %rcx
    cld
    rep movsb
    ret
.size nr_repeat_asm, .-nr_repeat_asm
.section .note.GNU-stack,"",@progbits
