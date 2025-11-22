// SPDX-License-Identifier: BSD-3-Clause

#include <stddef.h>
#include <stdint.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>

//Structurile din elf.h pentru a vedea componentele si ce inseamna fiecare
/**
 *typedef struct {
 *	unsigned char	e_ident[16]; //elf magic number
 *	uint16_t	e_type;
 *	uint16_t	e_machine;
 *	uint32_t	e_version;
 *	uint64_t	e_entry;     //entry point
 *	uint64_t	e_phoff;     //offset ul unde incep program headers
 *	uint16_t	e_phentsize;    //dimensiunea unui program header
 *	uint16_t	e_phnum;        //cate program headers sunt
 *} Elf64_Ehdr
 */

/**
 *typedef struct {
 *	uint32_t   p_type;   //PT_LOAD, PT_DYNAMIC, etc.
 *	uint64_t   p_offset; //unde incepe segmentul in fisier
 *	uint64_t   p_vaddr;  //unde trebuie pus in memorie
 *	uint64_t   p_filesz; //dimensiunea segmentului in fisier
 *	uint64_t   p_memsz;  //dimensiunea segmentului in memorie
 *	uint32_t   p_flags;  //PF_R, PF_W, PF_X
 *} Elf64_Phdr;
 */

#define DIE(assertion, call_description)								\
do {																	\
	if (assertion) {													\
		fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);				\
		perror(call_description);										\
	}																	\
} while (0)

#define ELFCLASS64 2

#define STACK_SIZE (8 * 1024 * 1024) //8 MB

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */
	char *elf_bytes = (char *) elf_contents;

	if (elf_bytes[EI_MAG0] != ELFMAG0 || elf_bytes[EI_MAG1] != ELFMAG1 || elf_bytes[EI_MAG2] != ELFMAG2 || elf_bytes[EI_MAG3] != ELFMAG3) {
		DIE(1, "Not a valid ELF file");
		exit(3);
	} else if (elf_bytes[EI_CLASS] != ELFCLASS64) {
		DIE(1, "Not a 64-bit ELF");
		exit(4);
	}

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */
	Elf64_Ehdr *elf_ehdr = (Elf64_Ehdr *) elf_contents;
	Elf64_Phdr *elf_phdr = (Elf64_Phdr *)(elf_bytes + elf_ehdr->e_phoff);

	for (int i = 0; i < elf_ehdr->e_phnum; i++) {
		if (elf_phdr[i].p_type != PT_LOAD)
			continue;

		void *src = elf_bytes + elf_phdr[i].p_offset;
		//aliniez adresa la fiecare pagina
		uint64_t aligned_addr = elf_phdr[i].p_vaddr & ~(getpagesize() - 1);
		//offset-ul fata de adresa aliniata
		uint64_t aligned_offset = elf_phdr[i].p_vaddr - aligned_addr;

		void *mapped_memory = mmap((void *)aligned_addr, elf_phdr[i].p_memsz + aligned_offset, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (mapped_memory == MAP_FAILED) {
			DIE(1, "mmap failed");
			exit(1);
		}

		memcpy(mapped_memory + aligned_offset, src, elf_phdr[i].p_filesz);

		/**
		 * TODO: Load Memory Regions with Correct Permissions
		 * For each PT_LOAD segment:
		 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
		 *	- Use mprotect() or map with the correct permissions directly using mmap().
		 */

		int prot = 0;

		if (elf_phdr[i].p_flags & PF_R)
			prot |= PROT_READ;
		if (elf_phdr[i].p_flags & PF_W)
			prot |= PROT_WRITE;
		if (elf_phdr[i].p_flags & PF_X)
			prot |= PROT_EXEC;

		mprotect((void *)aligned_addr, elf_phdr[i].p_memsz + aligned_offset, prot);
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	void *sp = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (sp == MAP_FAILED) {
		DIE(1, "mmap sp failed");
		exit(1);
	}

	//incepe de la adresa cea mai mare
	void *sp_top = sp + STACK_SIZE;

	//aliniez stack-ul la 16 bytes, se asigura ca sp e mereu multiplu de 16
	sp = (void *)((uintptr_t)sp_top & ~0xF);

	int envc = 0;

	while (envp[envc] != NULL)
		envc++;

	//trec peste dimensiunea stringurilor in stiva
	int size_envc_strings = 0;

	for (int i = 0; i < envc; i++)
		size_envc_strings += strlen(envp[i]) + 1;

	sp -= size_envc_strings;
	sp = (void *)((uintptr_t)sp & ~0xF);

	int size_argv_strings = 0;

	for (int i = 0; i < argc; i++)
		size_argv_strings += strlen(argv[i]) + 1;

	sp -= size_argv_strings;
	sp = (void *)((uintptr_t)sp & ~0xF);

	char *sp_srings = (char *)sp;

	//copiez stringurile in stiva si retin adresele in vectori
	char **argv_pointers = malloc(argc * sizeof(char *));

	if (argv_pointers == NULL) {
		DIE(1, "malloc argv_pointers failed");
		exit(1);
	}

	for (int i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]) + 1;

		memcpy(sp_srings, argv[i], len);
		argv_pointers[i] = sp_srings;
		sp_srings += len;
	}

	char **envp_pointers = malloc(envc * sizeof(char *));

	if (envp_pointers == NULL) {
		DIE(1, "malloc envp_ptrs failed");
		exit(1);
	}

	for (int i = 0; i < envc; i++) {
		size_t len = strlen(envp[i]) + 1;

		memcpy(sp_srings, envp[i], len);
		envp_pointers[i] = sp_srings;
		sp_srings += len;
	}

	//pun de la mine 16 bytes "random" pentru AT_RANDOM
	uint8_t random_bytes[16] = {"ceva random"};

	sp -= 16;
	sp = (void *)((uintptr_t)sp & ~0xF);
	memcpy(sp, random_bytes, 16);
	void *at_random = sp;

	//creez vectorul auxv cu toate perechile de pe lwn.net in ordine
	Elf64_auxv_t auxv[20];
	int auxv_idx = 0;

	auxv[auxv_idx].a_type = AT_SYSINFO_EHDR;
	auxv[auxv_idx].a_un.a_val = 0;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_HWCAP;
	auxv[auxv_idx].a_un.a_val = 0;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_PAGESZ;
	auxv[auxv_idx].a_un.a_val = getpagesize();
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_CLKTCK;
	auxv[auxv_idx].a_un.a_val = sysconf(_SC_CLK_TCK);
	auxv_idx++;

	void *phdr_addr = elf_bytes + elf_ehdr->e_phoff;

	auxv[auxv_idx].a_type = AT_PHDR;
	auxv[auxv_idx].a_un.a_val = (uint64_t)phdr_addr;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_PHENT;
	auxv[auxv_idx].a_un.a_val = elf_ehdr->e_phentsize;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_PHNUM;
	auxv[auxv_idx].a_un.a_val = elf_ehdr->e_phnum;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_BASE;
	auxv[auxv_idx].a_un.a_val = 0;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_FLAGS;
	auxv[auxv_idx].a_un.a_val = 0;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_ENTRY;
	auxv[auxv_idx].a_un.a_val = elf_ehdr->e_entry;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_UID;
	auxv[auxv_idx].a_un.a_val = getuid();
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_EUID;
	auxv[auxv_idx].a_un.a_val = geteuid();
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_GID;
	auxv[auxv_idx].a_un.a_val = getgid();
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_EGID;
	auxv[auxv_idx].a_un.a_val = getegid();
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_SECURE;
	auxv[auxv_idx].a_un.a_val = 0;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_RANDOM;
	auxv[auxv_idx].a_un.a_val = (uint64_t)at_random;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_EXECFN;
	auxv[auxv_idx].a_un.a_val = (uint64_t)filename;
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_PLATFORM;
	auxv[auxv_idx].a_un.a_val = (uint64_t)"x86_64";
	auxv_idx++;

	auxv[auxv_idx].a_type = AT_NULL;
	auxv[auxv_idx].a_un.a_val = 0;
	auxv_idx++;

	//pun pe stiva auxv, envp, argv si argc
	sp -= sizeof(Elf64_auxv_t) * auxv_idx;
	sp -= sizeof(char *) * (envc + 1);
	sp -= sizeof(char *) * (argc + 1);
	sp -= sizeof(int);
	sp = (void *)((uintptr_t)sp & ~0xF);

	uint64_t *stack_p = (uint64_t *)sp;

	*stack_p = argc;
	stack_p++;

	for (int i = 0; i < argc; i++) {
		*stack_p = (uint64_t)argv_pointers[i];
		stack_p++;
	}
	*stack_p = 0;
	stack_p++;

	for (int i = 0; i < envc; i++) {
		*stack_p = (uint64_t)envp_pointers[i];
		stack_p++;
	}
	*stack_p = 0;
	stack_p++;

	for (int i = 0; i < auxv_idx; i++) {
		*stack_p = auxv[i].a_type;
		stack_p++;
		*stack_p = auxv[i].a_un.a_val;
		stack_p++;
	}

	free(argv_pointers);
	free(envp_pointers);
	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	void (*entry)() = (void (*)())elf_ehdr->e_entry;

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
