all:
	gcc -Wall -Werror -O3 -s -o ptrace-injector main.c
	gcc -Wall -Werror -O3 -s -o example example.c
	nasm -f elf64 shellcode.nasm && ld -s -o shellcode shellcode.o && rm shellcode.o
clean:
	rm ptrace-injector example shellcode