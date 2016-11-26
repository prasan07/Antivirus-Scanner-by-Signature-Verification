#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <asm/syscall.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include "udis86.h"
#include "mem.h"
#include <linux/module.h>

#define WP_DISABLE	write_cr0(read_cr0() & (~ X86_CR0_WP))
#define WP_ENABLE	write_cr0(read_cr0() | (X86_CR0_WP))
#define AT_EMPTY_PATH		0x1000	/* Allow empty relative pathname */
#define MAX_RELATIVE_CALL_OFFSET (150)

asmlinkage extern long (*sysptr)(void);

void **table;

asmlinkage long (*old_open)(const char __user *file, int flags, umode_t mode);

asmlinkage long (*old_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);
asmlinkage long (*old_execveat)(int dfd, const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp, int flags);

char *path = "/usr/src/linux-stable/Antivirus/antivirus";

char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL};

/*
long MEM_find_insn_off(unsigned long mem_addr,
				size_t block_size,
				int insn_type,
				size_t insn_size) {
	ud_t ud;

	ud_init(&ud);
	ud_set_input_buffer(&ud, (char * ) mem_addr, block_size);
	ud_set_mode(&ud, 64);

	while(ud_disassemble(&ud)) {

		if ((insn_type == ud.mnemonic) && 
				(insn_size == ud_insn_len(&ud)) ) {
			return ud_insn_off(&ud);		
		}

	}
	
	return 1;
}
*/
/*******************************************************************
* Name:		MEM_patch_relative_call
* Description:	This function searches for a relative call in a
*		given memory region. In case a relative call is
*		found, it will patch it to call `new_call_addr`.
*		It saves the original called address in 
*		`orig_call_addr`.
*******************************************************************/
/*
int MEM_patch_relative_call(unsigned long mem_addr,
				size_t block_size,
				unsigned long new_call_addr,
				unsigned long * orig_call_addr) {
	int ret = 0;
	long call_insn_offset; 
	unsigned long call_insn_addr;
	unsigned long call_relative_val;
	unsigned long new_call_relative_val;
	unsigned int level;
        pte_t *pte;


	// Find the relative call instruction (E8) offset
	call_insn_offset = MEM_find_insn_off(mem_addr,
						block_size, UD_Icall, 
						RELATIVE_CALL_SIZE);	
	if (call_insn_offset == 1) {
		printk("Error patching the relative call address\n");
		ret = 1;
		goto cleanup;
	}

	// Calculate the call instruction address
	call_insn_addr = (mem_addr + call_insn_offset);

	pte = lookup_address((unsigned long)call_insn_addr, &level);
	if (pte == NULL) {
		ret = 1;
		printk("UNABLE TO LOOKUP PAGE WHILE ATTEMPTING TO PATH THE CALL\n");
		goto cleanup;
	}
	pte->pte |= _PAGE_RW;
	ret = set_memory_rw(PAGE_ALIGN((unsigned long)call_insn_addr) - PAGE_SIZE, 1);
//	MEM_make_rw(call_insn_addr);

	call_relative_val = (*((int *) (call_insn_addr + 1)));

	// Calculate the relative value for calling the new_sys_execve
	new_call_relative_val = ((unsigned long) new_call_addr - call_insn_addr - RELATIVE_CALL_SIZE);

	// Save the address of the original sys_execve
	if (NULL != orig_call_addr) {
		printk("ORIGINAL CALL ADDR IS NOT NULL\n");
		*orig_call_addr = call_insn_addr + RELATIVE_CALL_SIZE + call_relative_val;
	}

	// Patch
	(*((int*)(call_insn_addr + 1))) = (int) new_call_relative_val;

	set_memory_ro(PAGE_ALIGN((unsigned long)call_insn_addr) - PAGE_SIZE, 1);
	pte->pte &= ~_PAGE_RW;
cleanup:
	return ret;
}
*/



asmlinkage long trapper(void)
{
	printk("\nKernel intercepted by the new module\n");
	return 0;
}


asmlinkage long new_open(const char __user *file, int flags, umode_t mode)
{
	long ret = 0;
	struct kstat statbuf;
	char *argv[] = {path, file, NULL};
	if (vfs_stat(file, &statbuf) != 0) {
		printk("Unable to determine if regular file or dir or link\n");
		goto open;
	} else {
		if (statbuf.mode & S_IFREG)
			printk("REGULAR FILE\n");
		else {
			printk("NOT A REGULAR FILE\n");
			goto open;
		}
	}
	ret = call_usermodehelper(argv[0], argv, envp, 1);
	if (ret > 0) {
		printk("Virus detected in file %s\n", file);
		goto end;
	} else if(ret < 0) {
		printk("Error while determining presence of virus in file %s\n", file);
		goto end;
	} else {
		printk("No virus found, file %s can be opened\n", file);
	}
open:
	ret = old_open(file, flags, mode);
	printk("File %s has been opened with mode %d and flags %d\n", file, mode, flags);
	printk("\n");
end:
	return ret;
}


asmlinkage long new_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret = 0;
//	struct filename *fname;
	//printk(KERN_ALERT "\nSTARTING EXECVE\n");
	//fname = getname(filename);
	//printk(KERN_ALERT "GOT EXECUTABLE NAME\n");
	//ret = PTR_ERR(fname);
	//if (IS_ERR(fname)) {
	//	goto end;
	//}
	printk(KERN_ALERT "(BEFORE EXEC)File %s has been exec\n", filename);
	//ret = do_execve(fname->name, argv, envp, regs);
	ret = old_execve(filename, argv, envp);
	printk(KERN_ALERT "(AFTER EXEC)File %s has been exec\n", filename);
	
	//putname(fname);
//end:
	return ret;
}

static int __init init_sys_trapper(void)
{
	unsigned int level;
	pte_t *pte;
	int ret = -1;
	unsigned long old_stub_execve;
	unsigned long old_call_addr;

	printk("\nInited new module\n");
	printk("Syscall table is at : %p\n", sys_call_table);

	if (sysptr == NULL)
		sysptr = trapper;

	table = (void **)sys_call_table;
	if (!table) {
		printk("COULD NOT FIND SYSCALL TABLE\n");
		goto end;
	}
	printk("Syscall table correctly copied : %p\n", table);

	WP_DISABLE;
	pte = lookup_address((unsigned long)table, &level);
	if (pte == NULL) {
		printk("UNABLE TO LOOKUP PAGE AT THE START\n");
		goto end;
	}
	pte->pte |= _PAGE_RW;
	ret = set_memory_rw(PAGE_ALIGN((unsigned long)table) - PAGE_SIZE, 1);

//	old_open = table[__NR_open];
//	table[__NR_open] = new_open;
	
	old_stub_execve = ((unsigned long *) (table))[__NR_execve];
	ret = MEM_patch_relative_call(old_stub_execve,
		MAX_RELATIVE_CALL_OFFSET,
		(unsigned long) new_execve, &old_call_addr);
	if (ret == 0) {
		printk("No issues with patching relative call\n");
		old_execve = (void *)old_call_addr;
	}

	set_memory_ro(PAGE_ALIGN((unsigned long)table) - PAGE_SIZE, 1);
	pte->pte &= ~_PAGE_RW;
end:
	WP_ENABLE;

	return 0;
}



static void  __exit exit_sys_trapper(void)
{
	unsigned int level;
	pte_t *pte;
	int ret = -1;
	unsigned long old_stub_execve;

	if (sysptr != NULL)
		sysptr = NULL;

	printk("\nSyscall table correct while exiting : %p\n", table);

	WP_DISABLE;
	pte = lookup_address((unsigned long)table, &level);
	if (pte == NULL) {
		printk("\nUNABLE TO LOOKUP PAGE AT THE START\n");
		goto end;
	}
	pte->pte |= _PAGE_RW;
	ret = set_memory_rw(PAGE_ALIGN((unsigned long)table) - PAGE_SIZE, 1);

//	table[__NR_open] = old_open;

	old_stub_execve = ((unsigned long *) (table))[__NR_execve];
	MEM_patch_relative_call(old_stub_execve,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) old_execve, NULL);

	set_memory_ro(PAGE_ALIGN((unsigned long)table) - PAGE_SIZE, 1);
	pte->pte &= ~_PAGE_RW;
end:
	WP_ENABLE;

	printk("Exited new module\n");
}


module_init(init_sys_trapper);
module_exit(exit_sys_trapper);
MODULE_LICENSE("GPL");

