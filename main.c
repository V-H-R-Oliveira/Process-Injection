#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

void *mapFile(const char *path, long *filesize)
{
    FILE *file = fopen(path, "rb");
    int fd;
    void *content;

    if (!file)
    {
        perror("fopen error:");
        exit(EXIT_FAILURE);
    }

    if (fseek(file, 0, SEEK_END) == -1)
    {
        fclose(file);
        perror("fseek error:");
        exit(EXIT_FAILURE);
    }

    fd = fileno(file);

    if (fd == -1)
    {
        fclose(file);
        perror("fileno error:");
        exit(EXIT_FAILURE);
    }

    *filesize = ftell(file);
    rewind(file);

    if (content = mmap(NULL, *filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0), content == MAP_FAILED)
    {
        fclose(file);
        perror("mmap error:");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf("[+] %s was mapped into memory.\n", path);
    return content;
}

void freeContent(void *content, long filesize)
{
    if (munmap(content, filesize) == 0)
        printf("[+] The block memory of size %ld bytes was deallocated from the memory.\n", filesize);
}

void injectShellcode(pid_t pid, void *rip_addr, char *content, long filesize)
{
    Elf64_Ehdr *elf_headers = (Elf64_Ehdr *)content;
    Elf64_Shdr *section_headers = (Elf64_Shdr *)((unsigned char *)elf_headers + elf_headers->e_shoff);
    Elf64_Off text_sec_init = 0;
    Elf64_Xword text_sec_size = 0;
    char *sectionTab = &content[section_headers[elf_headers->e_shstrndx].sh_offset];

    for (int i = 1; i < elf_headers->e_shnum; ++i)
    {
        if (strncmp(&sectionTab[section_headers[i].sh_name], ".text", 5) == 0)
        {
            text_sec_init = section_headers[i].sh_offset;
            text_sec_size = section_headers[i].sh_size;
            break;
        }
    }

    for (Elf64_Xword i = 0; i < text_sec_size; ++i, ++rip_addr)
    {
        if (ptrace(PTRACE_POKETEXT, pid, rip_addr, *(uint32_t *)(content + text_sec_init + i)) == -1)
        {
            freeContent(content, filesize);
            perror("ptrace poketext error:");
            exit(EXIT_FAILURE);
        }
    }

    freeContent(content, filesize);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage %s <pid> <shellcode>\n", *argv);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    struct user_regs_struct regs;
    const char *path = argv[2];
    char *content;
    long filesize;

    if (getuid() != 0)
    {
        puts("You must be root to be able to attach.");
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        perror("Ptrace attach error:");
        return 1;
    }

    wait(NULL);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        perror("Ptrace getregs error:");
        return 1;
    }

    content = mapFile(path, &filesize);
    injectShellcode(pid, (void *)regs.rip, content, filesize);

    regs.rip += 2; // detach subtracts 2 bytes of rip

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        perror("ptrace_setregs error:");
        return 1;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        perror("Ptrace detach error:");
        return 1;
    }

    return 0;
}