/* XXX HACKS to use kernel header files from user space */
#define __KERNEL__
#define _ASM_X86_ELF_H
/* XXX HACKS to use kernel header files from user space */
#define ELF_CLASS ELFCLASS32

//typedef __int128 int128_t;
//typedef unsigned __int128 uint128_t;
#include <linux/elf.h>
#include <linux/elf-em.h>
#include <string.h>

/* XXX HACK to prevent double definition of size_t in user space headers
 * and kernel headers
 */
#define __ssize_t_defined
#include <stdio.h>

#define ELF_DATA ELFDATA2LSB
#define EM_XTENSA 94

#define MAX_MEM_SECTIONS        16
#define MAX_MEM_SECTION_LENGTH  (7*1024*1024) // 7M Bytes

struct _mem_section {
    unsigned int start_addr;
    unsigned int length;
    unsigned char *data;
};

struct _mem_section mem_section[MAX_MEM_SECTIONS];
unsigned int num_section_valid = 0;

FILE *fp;
struct elfhdr elf2;

#if 0
/*
 * Core dumping helper functions.  These are the only things you should
 * do on a core-file: use only these functions to write out all the
 * necessary info.
 */
int dump_emit(struct coredump_params *cprm, const void *addr, int nr)
{
	struct file *file = cprm->file;
	loff_t pos = file->f_pos;
	ssize_t n;
	if (cprm->written + nr > cprm->limit)
		return 0;
	while (nr) {
		if (dump_interrupted())
			return 0;
		n = __kernel_write(file, addr, nr, &pos);
		if (n <= 0)
			return 0;
		file->f_pos = pos;
		cprm->written += n;
		nr -= n;
	}
	return 1;
}
#endif

static void fill_elf_header(struct elfhdr *elf, int segs,
			    u16 machine, u32 flags)
{
	memset(elf, 0, sizeof(*elf));

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

#if 0
static int fill_note_info(struct elfhdr *elf, int phdrs,
			  struct elf_note_info *info,
			  const siginfo_t *siginfo, struct pt_regs *regs)
{
	struct list_head *t;
	struct core_thread *ct;
	struct elf_thread_status *ets;

	if (!elf_note_info_init(info))
		return 0;

	for (ct = current->mm->core_state->dumper.next;
					ct; ct = ct->next) {
		ets = kzalloc(sizeof(*ets), GFP_KERNEL);
		if (!ets)
			return 0;

		ets->thread = ct->task;
		list_add(&ets->list, &info->thread_list);
	}

	list_for_each(t, &info->thread_list) {
		int sz;

		ets = list_entry(t, struct elf_thread_status, list);
		sz = elf_dump_thread_status(siginfo->si_signo, ets);
		info->thread_status_size += sz;
	}
	/* now collect the dump for the current */
	memset(info->prstatus, 0, sizeof(*info->prstatus));
	fill_prstatus(info->prstatus, current, siginfo->si_signo);
	elf_core_copy_regs(&info->prstatus->pr_reg, regs);

	/* Set up header */
	fill_elf_header(elf, phdrs, ELF_ARCH, ELF_CORE_EFLAGS);

	/*
	 * Set up the notes in similar form to SVR4 core dumps made
	 * with info from their /proc.
	 */

	fill_note(info->notes + 0, "CORE", NT_PRSTATUS,
		  sizeof(*info->prstatus), info->prstatus);
	fill_psinfo(info->psinfo, current->group_leader, current->mm);
	fill_note(info->notes + 1, "CORE", NT_PRPSINFO,
		  sizeof(*info->psinfo), info->psinfo);

	fill_siginfo_note(info->notes + 2, &info->csigdata, siginfo);
	fill_auxv_note(info->notes + 3, current->mm);
	info->numnote = 4;

	if (fill_files_note(info->notes + info->numnote) == 0) {
		info->notes_files = info->notes + info->numnote;
		info->numnote++;
	}

	/* Try to dump the FPU. */
	info->prstatus->pr_fpvalid = elf_core_copy_task_fpregs(current, regs,
							       info->fpu);
	if (info->prstatus->pr_fpvalid)
		fill_note(info->notes + info->numnote++,
			  "CORE", NT_PRFPREG, sizeof(*info->fpu), info->fpu);
#ifdef ELF_CORE_COPY_XFPREGS
	if (elf_core_copy_task_xfpregs(current, info->xfpu))
		fill_note(info->notes + info->numnote++,
			  "LINUX", ELF_CORE_XFPREG_TYPE,
			  sizeof(*info->xfpu), info->xfpu);
#endif

	return 1;
}

/*
 * Actual dumper
 *
 * This is a two-pass process; first we find the offsets of the bits,
 * and then they are actually written out.  If we run out of core limit
 * we just truncate.
 */
static int elf_core_dump(struct coredump_params *cprm)
{
	int has_dumped = 0;
	mm_segment_t fs;
	int segs, i;
	size_t vma_data_size = 0;
	struct vm_area_struct *vma, *gate_vma;
	struct elfhdr *elf = NULL;
	loff_t offset = 0, dataoff;
	struct elf_note_info info = { };
	struct elf_phdr *phdr4note = NULL;
	struct elf_shdr *shdr4extnum = NULL;
	Elf_Half e_phnum;
	elf_addr_t e_shoff;
	elf_addr_t *vma_filesz = NULL;

	/*
	 * We no longer stop all VM operations.
	 * 
	 * This is because those proceses that could possibly change map_count
	 * or the mmap / vma pages are now blocked in do_exit on current
	 * finishing this core dump.
	 *
	 * Only ptrace can touch these memory addresses, but it doesn't change
	 * the map_count or the pages allocated. So no possibility of crashing
	 * exists while dumping the mm->vm_next areas to the core file.
	 */
  
	/* alloc memory for large data structures: too large to be on stack */
	elf = kmalloc(sizeof(*elf), GFP_KERNEL);
	if (!elf)
		goto out;
	/*
	 * The number of segs are recored into ELF header as 16bit value.
	 * Please check DEFAULT_MAX_MAP_COUNT definition when you modify here.
	 */
	segs = current->mm->map_count;
	segs += elf_core_extra_phdrs();

	gate_vma = get_gate_vma(current->mm);
	if (gate_vma != NULL)
		segs++;

	/* for notes section */
	segs++;

	/* If segs > PN_XNUM(0xffff), then e_phnum overflows. To avoid
	 * this, kernel supports extended numbering. Have a look at
	 * include/linux/elf.h for further information. */
	e_phnum = segs > PN_XNUM ? PN_XNUM : segs;

	/*
	 * Collect all the non-memory information about the process for the
	 * notes.  This also sets up the file header.
	 */
	if (!fill_note_info(elf, e_phnum, &info, cprm->siginfo, cprm->regs))
		goto cleanup;

	has_dumped = 1;

	fs = get_fs();
	set_fs(KERNEL_DS);

	offset += sizeof(*elf);				/* Elf header */
	offset += segs * sizeof(struct elf_phdr);	/* Program headers */

	/* Write notes phdr entry */
	{
		size_t sz = get_note_info_size(&info);

		sz += elf_coredump_extra_notes_size();

		phdr4note = kmalloc(sizeof(*phdr4note), GFP_KERNEL);
		if (!phdr4note)
			goto end_coredump;

		fill_elf_note_phdr(phdr4note, sz, offset);
		offset += sz;
	}

	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);

	vma_filesz = kmalloc_array(segs - 1, sizeof(*vma_filesz), GFP_KERNEL);
	if (!vma_filesz)
		goto end_coredump;

	for (i = 0, vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		unsigned long dump_size;

		dump_size = vma_dump_size(vma, cprm->mm_flags);
		vma_filesz[i++] = dump_size;
		vma_data_size += dump_size;
	}

	offset += vma_data_size;
	offset += elf_core_extra_data_size();
	e_shoff = offset;

	if (e_phnum == PN_XNUM) {
		shdr4extnum = kmalloc(sizeof(*shdr4extnum), GFP_KERNEL);
		if (!shdr4extnum)
			goto end_coredump;
		fill_extnum_info(elf, shdr4extnum, e_shoff, segs);
	}

	offset = dataoff;

	if (!dump_emit(cprm, elf, sizeof(*elf)))
		goto end_coredump;

	if (!dump_emit(cprm, phdr4note, sizeof(*phdr4note)))
		goto end_coredump;

	/* Write program headers for segments dump */
	for (i = 0, vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		struct elf_phdr phdr;

		phdr.p_type = PT_LOAD;
		phdr.p_offset = offset;
		phdr.p_vaddr = vma->vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = vma_filesz[i++];
		phdr.p_memsz = vma->vm_end - vma->vm_start;
		offset += phdr.p_filesz;
		phdr.p_flags = vma->vm_flags & VM_READ ? PF_R : 0;
		if (vma->vm_flags & VM_WRITE)
			phdr.p_flags |= PF_W;
		if (vma->vm_flags & VM_EXEC)
			phdr.p_flags |= PF_X;
		phdr.p_align = ELF_EXEC_PAGESIZE;

		if (!dump_emit(cprm, &phdr, sizeof(phdr)))
			goto end_coredump;
	}

	if (!elf_core_write_extra_phdrs(cprm, offset))
		goto end_coredump;

 	/* write out the notes section */
	if (!write_note_info(&info, cprm))
		goto end_coredump;

	if (elf_coredump_extra_notes_write(cprm))
		goto end_coredump;

	/* Align to page */
	if (!dump_skip(cprm, dataoff - cprm->written))
		goto end_coredump;

	for (i = 0, vma = first_vma(current, gate_vma); vma != NULL;
			vma = next_vma(vma, gate_vma)) {
		unsigned long addr;
		unsigned long end;

		end = vma->vm_start + vma_filesz[i++];

		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			struct page *page;
			int stop;

			page = get_dump_page(addr);
			if (page) {
				void *kaddr = kmap(page);
				stop = !dump_emit(cprm, kaddr, PAGE_SIZE);
				kunmap(page);
				page_cache_release(page);
			} else
				stop = !dump_skip(cprm, PAGE_SIZE);
			if (stop)
				goto end_coredump;
		}
	}
	dump_truncate(cprm);

	if (!elf_core_write_extra_data(cprm))
		goto end_coredump;

	if (e_phnum == PN_XNUM) {
		if (!dump_emit(cprm, shdr4extnum, sizeof(*shdr4extnum)))
			goto end_coredump;
	}

end_coredump:
	set_fs(fs);

cleanup:
	free_note_info(&info);
	kfree(shdr4extnum);
	kfree(vma_filesz);
	kfree(phdr4note);
	kfree(elf);
out:
	return has_dumped;
}
#endif

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

}

static int write_elf_header()
{
    struct elfhdr *elf;

    /* Write and costruct ELF header */ 
    elf = (struct elfhdr *)malloc(sizeof(struct elfhdr));
	fill_elf_header(elf, num_section_valid, EM_XTENSA, 0x300);
    fwrite((void *)elf, sizeof(struct elfhdr), 1, fp);

    free((void *)elf);

    return 0;
}

int parse_dump_file(char *dump_file)
{
    FILE *fp_dump;
    unsigned char line[80];
    unsigned int addr, value;
    unsigned char *temp_data;
    unsigned int prev_addr;
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
        sscanf(line, "%x:%x\n", &addr, &value);
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
        printf("%x %d \n",mem_section[i].start_addr, mem_section[i].length);  
    }

    free(temp_data);
    fclose(fp_dump);
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
}




