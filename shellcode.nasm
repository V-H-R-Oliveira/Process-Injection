[bits 64]
[SECTION .text]
	global _start

_start:
	push rsp
	push rdx
	jmp short ender

	starter:
        push 1
		pop rax
		push rax
		pop rdi
		pop rbx
		push rbx
		pop rsi
		mov rdx, 35
		syscall

		pop rdx
		pop rsp

		push 60
		pop rax
		xor rdi, rdi
		syscall   
	ender:
		call starter
		db '### Infected by Binary Newbie ###', 0xa
