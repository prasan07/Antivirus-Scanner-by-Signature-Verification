//#include <linux/linkage.h>
//#include <linux/moduleloader.h>
//#include <linux/fs.h>
//#include <asm/syscall.h>
//#include <asm/cacheflush.h>
//#include <asm/page.h>
#include <asm/pgtable_types.h>
//#include <asm/pgtable.h>
//#include <asm/ptrace.h>
//#include <linux/kernel.h>
//#include <linux/kmod.h>
//#include <linux/slab.h>
//#include <linux/stat.h>
//#include <linux/namei.h>
#include "mem.h"
#include "udis86.h"

/*
 * Provides read-write permission to the page of a given memory address
 */
int MEM_make_rw(unsigned long addr) {
	int ret = 0;
	pte_t * pte;
	unsigned int level;

	pte = lookup_address(addr, &level);
	if (NULL == pte) {
		ret = 1;
		goto cleanup;
	}

	if (0 == (pte->pte & _PAGE_RW)) {
		pte->pte |= _PAGE_RW;
	}

cleanup:
	return ret;
}

/*
 * This function gets a memory address, block size, asm instruction and its size.
 * It disassembles the memory region until it finds the given
 * instruction, or until it reaches the max block size.
 * Then, it returns the offset of the instruction
 * from the given address.
 */
long MEM_find_insn_off(unsigned long mem_addr,
				size_t block_size,
				int insn_type,
				size_t insn_size) {
	ud_t ud;

	ud_init(&ud);
	ud_set_input_buffer(&ud, (char * ) mem_addr, block_size);
	ud_set_mode(&ud, 64);

	/* Run over the memory region */
	while(ud_disassemble(&ud)) {

		if ((insn_type == ud.mnemonic) && 
				(insn_size == ud_insn_len(&ud)) ) {
			return ud_insn_off(&ud);		
		}

	}
	
	return 1;
}

/*
 * This function searches for a relative call in a given memory region.
 * In case a relative call is found, it will patch it to call a `new_call_addr`.
 * It saves the original called address in `orig_call_addr`.
 */
int MEM_patch_relative_call(unsigned long mem_addr,
				size_t block_size,
				unsigned long new_call_addr,
				unsigned long * orig_call_addr) {
	int ret = 0;
	long call_insn_offset; 
	unsigned long call_insn_addr;
	unsigned long call_relative_val;
	unsigned long new_call_relative_val;


	/* Find the relative call instruction (E8) offset */
	call_insn_offset = MEM_find_insn_off(mem_addr,
						block_size, UD_Icall, 
						RELATIVE_CALL_SIZE);	
	if (call_insn_offset == 1) {
		ret = 1;
		goto cleanup;
	}

	/* Calculate the call instruction address */
	call_insn_addr = (mem_addr + call_insn_offset);

	MEM_make_rw(call_insn_addr);

	call_relative_val = (*((int *) (call_insn_addr + 1)));

	/* Calculate the relative value for calling the new_execve */
	new_call_relative_val = ((unsigned long) new_call_addr - call_insn_addr - RELATIVE_CALL_SIZE);

	/* Save the address of the old_execve */
	if (NULL != orig_call_addr) {
		*orig_call_addr = call_insn_addr + RELATIVE_CALL_SIZE + call_relative_val;
	}

	/* Patch */
	(*((int*)(call_insn_addr + 1))) = (int) new_call_relative_val;

cleanup:
	return ret;
}
