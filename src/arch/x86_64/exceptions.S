.macro ISR_NOERR vector
.global isr_\vector
isr_\vector:
    push 0
    push \vector
    jmp exception_common
.endm

.macro ISR_ERR vector
.global isr_\vector
isr_\vector:
    push \vector
    jmp exception_common
.endm

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

.global isr_unhandled
isr_unhandled:
    push 0
    push 255
    jmp exception_common

exception_common:
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    and rsp, -16
    call exception_dispatch
    ud2

.p2align 3
.global isr_stub_table
isr_stub_table:
    .quad isr_0,  isr_1,  isr_2,  isr_3
    .quad isr_4,  isr_5,  isr_6,  isr_7
    .quad isr_8,  isr_9,  isr_10, isr_11
    .quad isr_12, isr_13, isr_14, isr_15
    .quad isr_16, isr_17, isr_18, isr_19
    .quad isr_20, isr_21, isr_22, isr_23
    .quad isr_24, isr_25, isr_26, isr_27
    .quad isr_28, isr_29, isr_30, isr_31

