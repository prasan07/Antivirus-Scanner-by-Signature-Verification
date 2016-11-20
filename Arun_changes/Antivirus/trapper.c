#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <asm/syscall.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>
#include <asm/pgtable.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/stat.h>


#define WP_DISABLE	write_cr0(read_cr0() & (~ X86_CR0_WP))
#define WP_ENABLE	write_cr0(read_cr0() | (X86_CR0_WP))

asmlinkage extern long (*sysptr)(void);

void **table;

long (*old_open)(const char __user *file, int flags, umode_t mode);

char *path = "/usr/src/linux-stable/Antivirus/antivirus";

char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL};

//static void free_antivirus(struct subprocess_info *info) {
//	kfree(info->argv[0]);
//	kfree(info->argv);
//}

asmlinkage long trapper(void)
{
//	struct subprocess_info *info;
//	int ret;
//	char *file_path = "/usr/src/linux-stable/Antivirus/samplee.txt";
//	char *argv[] = {"/usr/src/linux-stable/Antivirus/antivirus",
//			"/usr/src/linux-stable/Antivirus/sample.txt",
//			NULL};
//	char *argv[] = {path, file_path, NULL};
	printk("\nKernel intercepted by the new module\n");

//	argv[0] = "./usr/src/linux-stable/Antivirus/antivirus";
//	argv[0] = "/usr/bin/touch";
//	argv[1] = "/usr/src/linux-stable/Antivirus/sample.txt";
//	argv[2] = NULL;
//	ret = call_usermodehelper(argv[0], argv, envp, 1);
//	info = call_usermodehelper_setup(path, argv, NULL, GFP_KERNEL, NULL,
//					free_antivirus,NULL);
//	if (!info) {
//		kfree(argv);
//		return -ENOMEM;
//	} else {
//		call_usermodehelper_exec(info, 1);
//	}
//	kfree(argv[0]);
//	kfree(argv[1]);
//	kfree(argv);
//	if (ret < 0)
//		return ret;
	return 0;
}


asmlinkage long new_open(const char __user *file, int flags, umode_t mode)
{
	long ret = 0;
	struct kstat statbuf;
//	char *argv[] = {path, file, NULL};
	//ret = call_usermodehelper(argv[0], argv, envp, 1);
	if (ret > 0) {
		printk("\nVirus detected\n");
	//	goto end;
	} else if(ret < 0) {
		printk("\nError while determining presence of virus\n");
	//	goto end;
	} else {
		printk("No virus, file can be opened\n");
	}
	if (vfs_stat(file, &statbuf) != 0) {
		printk("Unable to determine if regular file or dir or link\n");
	} else {
		if (statbuf.mode & S_IFREG)
			printk("REGULAR FILE\n");
		else
			printk("NOT A REGULAR FILE\n");
	}
	ret = old_open(file, flags, mode);
	printk("File %s has been opened with mode %d and flags %d\n", file, mode, flags);
	printk("\n");
//end:
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

