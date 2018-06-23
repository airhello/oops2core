#ifndef _LINUX_BINFMTS_H
#define _LINUX_BINFMTS_H

/* Function parameter for binfmt->coredump */
struct coredump_params {
	const siginfo_t *siginfo;
	struct pt_regs *regs;
	struct file *file;
	unsigned long limit;
	unsigned long mm_flags;
	loff_t written;
};

#endif /* _LINUX_BINFMTS_H */

