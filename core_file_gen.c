
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <linux/elf.h>
#include <linux/elf-em.h>

#define MAX_MEM_SECTIONS        16
#define MAX_MEM_SECTION_LENGTH  (7*1024*1024) // 7M Bytes

struct _mem_section {
#if ELF_CLASS == ELFCLASS64
	uint64_t start_addr;
#else
    uint32_t start_addr;
#endif
    unsigned int length;
    unsigned char *data;
};

struct _mem_section mem_section[MAX_MEM_SECTIONS];
unsigned int num_section_valid = 0;

FILE *fp;
struct elfhdr elf2;

static void fill_elf_header(struct elfhdr *elf, int segs,
			    uint16_t machine, uint32_t flags)
{
	memset(elf, 0, sizeof(struct elfhdr));

	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS] = ELF_CLASS;
	elf->e_ident[EI_DATA] = ELF_DATA;
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELF_OSABI;

	elf->e_type = ET_CORE;
	elf->e_machine = machine;
	elf->e_version = EV_CURRENT;
	elf->e_phoff = sizeof(struct elfhdr);
	elf->e_flags = flags;
	elf->e_ehsize = sizeof(struct elfhdr);
	elf->e_phentsize = sizeof(struct elf_phdr);
	elf->e_phnum = segs;

	return;
}

static int write_elf_program_section()
{
    unsigned int offset;
    unsigned int i;

    if (num_section_valid) {
        struct elf_phdr phdr;
        offset = sizeof(struct elfhdr) + sizeof(struct elf_phdr) * num_section_valid;
    
        for (i=0;i<num_section_valid;i++) {
		    phdr.p_type = PT_LOAD;
		    phdr.p_offset = offset;
		    phdr.p_vaddr = mem_section[i].start_addr;
		    phdr.p_paddr = mem_section[i].start_addr;
		    phdr.p_filesz = mem_section[i].length;
		    phdr.p_memsz = mem_section[i].length;
		    offset += phdr.p_filesz;
		    phdr.p_flags =  PF_R | PF_W;
			//phdr.p_flags |= PF_X;
		    //phdr.p_align = ELF_EXEC_PAGESIZE;
		    phdr.p_align = 0x1;
            fwrite((void *)&phdr, sizeof(struct elf_phdr), 1, fp);
        }

        for (i=0;i<num_section_valid;i++) {
            fwrite((void *)mem_section[i].data, mem_section[i].length, 1, fp);
        }
    }
	return 0;
}

static int write_elf_header()
{
    struct elfhdr *elf;

    /* Write and costruct ELF header */ 
    elf = (struct elfhdr *)malloc(sizeof(struct elfhdr));
	fill_elf_header(elf, num_section_valid, EM_ARCH, 0x300);
    fwrite((void *)elf, sizeof(struct elfhdr), 1, fp);

    free((void *)elf);

    return 0;
}

int parse_dump_file(char *dump_file)
{
    FILE *fp_dump;
    char line[80];
#if ELF_CLASS==ELFCLASS64
	uint64_t prev_addr, addr;
#else
	uint32_t prev_addr, addr;
#endif
    unsigned int value;
    unsigned char *temp_data;
    unsigned int cur_length;
    unsigned int i;

    temp_data =  (unsigned char *)malloc(MAX_MEM_SECTION_LENGTH);

    printf("File: %s \n",dump_file);
    fp_dump = fopen(dump_file, "r");

    prev_addr = 0xFFFFFFFF;
    cur_length = 0;
    while (!feof(fp_dump)) {
        fgets(line, sizeof(line), fp_dump);
        if ((line[0] != '0') || (line[1] != 'x')) {
            continue;
        }
#if ELF_CLASS==ELFCLASS64
		sscanf(line, "%llx:%x\n", &addr, &value);
#else
		sscanf(line, "%x:%x\n", &addr, &value);
#endif
        if (prev_addr != (addr - 4)) {
            /* Start of new section */
            mem_section[num_section_valid].start_addr = addr;
            if ((num_section_valid) && (cur_length)) {
                mem_section[num_section_valid - 1].data = (unsigned char *)malloc(cur_length);
                memcpy((void *)mem_section[num_section_valid - 1].data, (void *)temp_data, cur_length);
                mem_section[num_section_valid - 1].length = cur_length;
            }
            cur_length = 0;
            num_section_valid ++;
        } 
        prev_addr = addr;
        memcpy((void *)(temp_data + cur_length), (void *)&value, 4);
        cur_length += 4;
    }
    if ((num_section_valid) && (cur_length)) {
        mem_section[num_section_valid - 1].data = (unsigned char *)malloc(cur_length);
        memcpy((void *)mem_section[num_section_valid - 1].data, (void *)temp_data, cur_length);
        mem_section[num_section_valid - 1].length = cur_length;
    }

    for (i=0;i<num_section_valid;i++) {
#if ELF_CLASS==ELFCLASS64
        printf("%llx %d \n", mem_section[i].start_addr, mem_section[i].length);
#else
        printf("%x %d \n", mem_section[i].start_addr, mem_section[i].length);
#endif
    }

    free(temp_data);
    fclose(fp_dump);
	return 0;
}

int main(int argc, char *argv[])
{

    if (argc < 2) {
        printf("usage: a.out <dump file> \n");
        exit(-1);
    }

    fp = fopen ("core", "w");
    parse_dump_file(argv[1]);
    write_elf_header();
    write_elf_program_section();
	
    fflush(fp);
    fclose(fp);
	return 0;
}

