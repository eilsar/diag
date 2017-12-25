/*
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>

#include "hdlc.h"
#include "mbuf.h"
#include "diag_peripheral_plugin.h"

int diag_handle_KeepAlive(void *dc, void *data);
int diag_fd = 0;
struct diag_cmd_registration_entry entry = { 0x4b320003, 0x4b320003, &diag_handle_KeepAlive };
struct diag_cmd_registration_table test_table = { { 1 }, &entry };

int debug_op = 0;

int diag_handle_KeepAlive(void *dc, void *data)
{
	int ret = 0;
	uint8_t len = 16;
	uint8_t *buf;
	int i = 0;

	if (debug_op)
		printf("Keep alive\n");

	buf = malloc(len);
	buf[i++] = 0x4b;
	buf[i++] = 0x32;
	buf[i++] = 0x03;
	for (;i < len;)
		buf[i++] = 0;

	ret = write(diag_fd, buf, len);

	if (debug_op)
		printf("wrote %d bytes to fd %d\n", ret, diag_fd);

	return 0;
}

void diag_get_cmd_registration_table(struct diag_cmd_registration_table **tbl_ptr)
{
	struct diag_cmd_registration_table *ptr = NULL;
	ptr = malloc(sizeof(struct diag_cmd_registration_table));
	ptr->hdr.num_of_entries = 1;
	ptr->table = malloc(sizeof(struct diag_cmd_registration_entry));
	memcpy(ptr->table, &entry, sizeof(struct diag_cmd_registration_entry));
	*tbl_ptr = ptr;
	return;
}

int diag_set_pipe(int fd)
{
	diag_fd = fd;
	if (debug_op)
		printf("fd = %d\n", diag_fd);
	return 0;
}

int diag_set_debug_level(int level)
{
	debug_op = level;
	return 0;
}
