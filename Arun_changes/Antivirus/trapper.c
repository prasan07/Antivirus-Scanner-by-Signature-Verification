#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <asm/syscall.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>
#include <asm/pgtable.h>
#include <linux/kernel.h>

#define WP_DISABLE	write_cr0(read_cr0() & (~ X86_CR0_WP))
#define WP_ENABLE	write_cr0(read_cr0() | (X86_CR0_WP))

asmlinkage extern long (*sysptr)(void);

void **table;
long (*old_open)(const char* file, int flags, int mode);

asmlinkage long trapper(void)
{
	printk("\nKernel intercepted by the new module\n");
	return 0;
}


asmlinkage long new_open(const char* file, int flags, int mode)
{
	long ret;
	ret = old_open(file, flags, mode);
	printk("File %s has been opened with mode %d and flags %d\n", file, mode, flags);
	return ret;
}

static int __init init_sys_trapper(void)
{
	unsigned int level;
	pte_t *pte;
	int ret = -1;

	printk("Inited new module\n");
	printk("\nSyscall table is at : %p\n", sys_call_table);

	if (sysptr == NULL)
		sysptr = trapper;

	table = (void **)sys_call_table;
	if (!table) {
		printk("\nCOULD NOT FIND SYSCALL TABLE\n");
		goto end;
	}
	printk("\nSyscall table correctly copied : %p\n", table);

	WP_DISABLE;
	pte = lookup_address((unsigned long)table, &level);
	if (pte == NULL) {
		printk("\nUNABLE TO LOOKUP PAGE AT THE START\n");
		goto end;
	}
	pte->pte |= _PAGE_RW;
	ret = set_memory_rw(PAGE_ALIGN((unsigned long)table) - PAGE_SIZE, 1);

	old_open = table[__NR_open];
	table[__NR_open] = new_open;

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

	table[__NR_open] = old_open;

	set_memory_ro(PAGE_ALIGN((unsigned long)table) - PAGE_SIZE, 1);
	pte->pte &= ~_PAGE_RW;
end:
	WP_ENABLE;

	printk("Exited new module\n");
}


module_init(init_sys_trapper);
module_exit(exit_sys_trapper);
MODULE_LICENSE("GPL");

