/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP This
 * program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version. This program is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * impl ied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details. You
 * should have received a copy of the GNU General Public License along
 * with this program. If not, see http://www.gnu.org/licenses.
*/

#include <proc/readproc.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "cli_utils.h"

static struct proc_t *
get_process_info(pid_t pid,
		 struct proc_t *proc)
{
	return get_proc_stats(pid, proc);
}

static void
print_process_info(struct proc_t *proc)
{
	printf("beginning address of text segment: %#lx\n", proc->start_code);
	printf("ending address of text segment: %#lx\n", proc->end_code);
	printf("address of bottom of stack: %#lx\n", proc->start_stack);
	printf("address kernel stack pointer: %#lx\n", proc->kstk_esp);
	printf("address kernel instruction pointer: %#lx\n", proc->kstk_eip);

	return;
}

int
get_proc_info(char *input)
{
	char *ptr;
	struct proc_t *proc = NULL;
	int pid_num;

	proc = (struct proc_t*)malloc(sizeof(struct proc_t));
	if (proc == NULL)
		return ENOMEM;

	if (input != NULL) {
		ptr = next_token(&input, " \t\r\n");
		if (ptr == NULL) {
			printf("Must provide process identifier\n");
			return 0;
		} else {
			pid_num = atoi(ptr);
			printf("Searching for info on pid: %d\n", pid_num);
			proc = get_process_info(pid_num, proc);
			if (proc != NULL)
				print_process_info(proc);
		}
	}

	free(proc);
	return 0;
}

void
display_process_list(void)
{
	int libflags = (PROC_FILLMEM |
			PROC_FILLSTAT |
			PROC_FILLSTATUS);
	PROCTAB *PT;
	proc_t *p;

	PT = openproc(libflags);

	if (!PT) {
		printf("error opening proctab\n");
		return;
	}

	while ((p = readproc(PT, NULL)) != NULL) {
		printf("%6d  %20s:\t%5ld\t%5lld\t%5lld\n",
		       p->tid, p->cmd, p->resident,
		       p->utime, p->stime);
		freeproc(p);
	}

	closeproc(PT);

	return;
}
