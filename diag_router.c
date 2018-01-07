/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 * Copyright (c) 2016, Linaro Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "diag.h"
#include "diag_dbg.h"
#include "list.h"
#include "mbuf.h"
#include "peripheral.h"
#include "util.h"

static int diag_cmd_dispatch(struct diag_client *client,
				uint8_t *ptr, size_t len)
{
	struct peripheral *peripheral;
	struct list_head *item;
	struct diag_cmd *dc;
	unsigned int key;
	int handled = 0;
	struct mbuf *fwd_packet;

	if (ptr[0] == DIAG_CMD_SUBSYS_DISPATCH)
		key = ptr[0] << 24 | ptr[1] << 16 | ptr[3] << 8 | ptr[2];
	else
		key = 0xff << 24 | 0xff << 16 | ptr[0];

	if (key == 0x4b320003) {
		fwd_packet = create_packet(ptr, len, ENCODE);
		if (fwd_packet)
			queue_push(&client->outq, fwd_packet);

		return 0;
	}

	list_for_each(item, &diag_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		if (key < dc->first || key > dc->last)
			continue;

		peripheral = dc->peripheral;
		diag_dbg(DIAG_DBG_MAIN, "Respond via peripheral %s\n", peripheral->name);
		fwd_packet = create_packet(ptr, len, peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE ? KEEP_AS_IS : ENCODE);
		if (fwd_packet == NULL)
			break;
		queue_push(&peripheral->channels[peripheral_ch_type_cmd].queue, fwd_packet);

		handled++;
	}

	return handled ? 0 : -ENOENT;
}

static int diag_rsp_bad_command(struct diag_client *client,
				 void *buf, size_t len)
{
	uint8_t *resp_buf;
	size_t resp_buf_len = len + 1;
	struct mbuf *resp_packet;

	resp_buf = malloc(resp_buf_len);
	if (!resp_buf) {
		warn("failed to allocate error buffer");

		return -ENOMEM;
	}

	resp_buf[0] = DIAG_CMD_RSP_BAD_COMMAND;
	memcpy(resp_buf + 1, buf, len);

	resp_packet = create_packet(resp_buf, resp_buf_len, ENCODE);
	free(resp_buf);
	if (resp_packet == NULL) {

		return -1;
	}

	queue_push(&client->outq, resp_packet);

	return 0;
}

int diag_client_handle_command(struct diag_client *client, void *buf, size_t len)
{
	int ret;

	ret = diag_cmd_dispatch(client, buf, len);
	if (ret < 0)
		ret = diag_rsp_bad_command(client, buf, len);

	return ret;
}
