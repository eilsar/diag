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
#include "diag_cntl.h"
#include "diag_dbg.h"
#include "list.h"
#include "masks.h"
#include "mbuf.h"
#include "peripheral.h"
#include "util.h"

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

struct list_head common_cmds = LIST_INIT(common_cmds);
struct list_head apps_cmds = LIST_INIT(apps_cmds);

static int diag_cmd_dispatch(struct diag_client *client,
				void *buf, size_t len)
{
	struct peripheral *peripheral;
	struct list_head *item;
	struct diag_cmd *dc;
	unsigned int key;
	uint8_t *ptr = buf;
	struct mbuf *resp_packet;

	if (ptr[0] == DIAG_CMD_SUBSYS_DISPATCH || ptr[0] == DIAG_CMD_SUBSYS_DISPATCH_V2) {
		key = ptr[0] << 24 | ptr[1] << 16 | ptr[3] << 8 | ptr[2];
		diag_dbg_dump(DIAG_DBG_ROUTER_DUMP, "subsys cmdid = ", ptr, 4);
	} else {
		key = 0xff << 24 | 0xff << 16 | ptr[0];
		diag_dbg_dump(DIAG_DBG_ROUTER_DUMP, "cmdid = ", ptr, 1);
	}

	if (key == DIAG_CMD_KEEP_ALIVE_KEY) {
		resp_packet = create_packet(ptr, len, ENCODE);
		if (resp_packet == NULL) {

			return -1;
		}

		queue_push(&client->outq, resp_packet);

		return 0;
	}

	list_for_each(item, &common_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		if (key < dc->first || key > dc->last) {
			continue;
		}

		diag_dbg(DIAG_DBG_ROUTER, "Respond via apps handler\n");

		return dc->cb(dc, client, buf, len);
	}

	list_for_each(item, &diag_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		if (key < dc->first || key > dc->last) {
			continue;
		}

		peripheral = dc->peripheral;

		diag_dbg(DIAG_DBG_ROUTER, "Respond via peripheral %s\n", peripheral->name);

		return dc->cb(dc, client, buf, len);
	}

	list_for_each(item, &apps_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		if (key < dc->first || key > dc->last) {
			continue;
		}

		diag_dbg(DIAG_DBG_ROUTER, "Respond via apps handler\n");

		return dc->cb(dc, client, buf, len);
	}

	return -ENOENT;
}

static int diag_rsp_bad_command(struct diag_client *client,
				 void *buf, size_t len, uint8_t bad_code)
{
	uint8_t *resp_buf;
	size_t resp_buf_len = len + 1;
	struct mbuf *resp_packet;

	if (posix_memalign((void **)&resp_buf, PACKET_ALLOC_ALIGNMENT, resp_buf_len)) {
		warn("failed to allocate error buffer");
		return -errno;
	}

	resp_buf[0] = bad_code;
	memcpy(resp_buf + 1, buf, len);

	resp_packet = create_packet(resp_buf, resp_buf_len, ENCODE);
	free(resp_buf);
	if (resp_packet == NULL) {

		return -1;
	}

	queue_push(&client->outq, resp_packet);

	return 0;
}

int diag_router_handle_incoming(struct diag_client *client, void *buf, size_t len)
{
	int ret;

	ret = diag_cmd_dispatch(client, buf, len);
	if (ret < 0)
		ret = diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_COMMAND);

	return ret;
}

int diag_cmd_forward_to_peripheral(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	struct peripheral *peripheral = dc->peripheral;
	struct mbuf *fwd_packet;

	if (!peripheral->channels[peripheral_ch_type_cmd].name) {
		warn("No command channel for peripheral %s!\n", peripheral->name);

		return -1;
	}

	fwd_packet = create_packet(buf, len, (peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE) ? KEEP_AS_IS : ENCODE);
	if (fwd_packet == NULL) {
		warn("failed to create packet");

		return -1;
	}

	queue_push(&peripheral->channels[peripheral_ch_type_cmd].queue, fwd_packet);

	diag_dbg(DIAG_DBG_ROUTER, "forwarded to %s\n", peripheral->name);

	return 0;
}

static void diag_router_send_msg_mask_to_all()
{
	int i;
	struct diag_ssid_range_t range;
	struct list_head *item;
	struct peripheral *peripheral;

	for (i = 0; i < MSG_MASK_TBL_CNT; i++) {
		range.ssid_first = ssid_first_arr[i];
		range.ssid_last = ssid_last_arr[i];
		list_for_each(item, &peripherals) {
			peripheral = container_of(item, struct peripheral, node);
			diag_cntl_send_msg_mask(peripheral, &range);
		}
	}
}

static int diag_router_handle_extended_build_id(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	struct mbuf *resp_packet;
	struct extended_build_id_request {
		uint8_t cmd_code;
	} *req = buf;
	struct {
		uint8_t cmd_code;
		uint8_t ver;
		uint8_t res0;
		uint32_t msm_rev;
		uint16_t res1;
		uint32_t mobile_model_number;
		char strings[];
	} __packed *resp;
	size_t resp_size;
	size_t string1_size = strlen(MOBILE_SOFTWARE_REVISION) + 1;
	size_t string2_size = strlen(MOBILE_MODEL_STRING) + 1;
	size_t strings_size = string1_size + string2_size;

	if (sizeof(*req) != len) {
		diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);

		return -1;
	}

	resp_size = sizeof(*resp) + strings_size;
	resp = malloc(resp_size);

	resp->cmd_code = req->cmd_code;
	resp->ver = DIAG_PROTOCOL_VERSION_NUMBER;
	resp->msm_rev = MSM_REVISION_NUMBER;
	resp->mobile_model_number = MOBILE_MODEL_NUMBER;
	strncpy(resp->strings, MOBILE_SOFTWARE_REVISION, string1_size);
	strncpy(resp->strings + string1_size, MOBILE_MODEL_STRING, string2_size);

	resp_packet = create_packet((uint8_t *)resp, resp_size, ENCODE);
	free(resp);
	if (resp_packet == NULL) {
		warn("failed to create packet");

		return -1;
	}

	queue_push(&client->outq, resp_packet);

	return 0;
}

static int diag_router_handle_diag_version(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	struct mbuf *resp_packet;
	struct diag_version_request {
		uint8_t cmd_code;
	} *req = buf;
	struct {
		uint8_t cmd_code;
		uint8_t ver;
	} __packed resp;

	if (sizeof(*req) != len) {
		diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);

		return -1;
	}

	resp.cmd_code = req->cmd_code;
	resp.ver = DIAG_PROTOCOL_VERSION_NUMBER;

	resp_packet = create_packet((uint8_t *)&resp, sizeof(resp), ENCODE);
	if (resp_packet == NULL) {
		warn("failed to create packet");

		return -1;
	}

	queue_push(&client->outq, resp_packet);

	return 0;
}

static struct diag_cmd *register_diag_cmd(unsigned int key,
		int(*cb)(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len),
		struct list_head *cmds)
{
	struct diag_cmd *dc = malloc(sizeof(struct diag_cmd));

	memset(dc, 0, sizeof(struct diag_cmd));
	dc->first = dc->last = key;
	dc->cb = cb;

	list_add(cmds, &dc->node);

	return dc;
}

static int diag_cmds_init()
{
	/* Register the cmd's that need to be handled by the router */
	register_diag_cmd(DIAG_CMD_DIAG_VERSION_KEY, diag_router_handle_diag_version, &apps_cmds);
	register_diag_cmd(DIAG_CMD_EXTENDED_BUILD_ID_KEY, diag_router_handle_extended_build_id, &apps_cmds);

	return 0;
}

static int diag_cmds_exit()
{
	struct list_head *item, *next;
	struct diag_cmd *dc;

	list_for_each_safe(item, next, &common_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		list_del(&dc->node);
		free(dc);
	}
	list_for_each_safe(item, next, &apps_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		list_del(&dc->node);
		free(dc);
	}

	return 0;
}

int diag_router_init()
{
	int ret;

	/* Init the masks */
	ret = diag_masks_init();
	if (ret)
		return ret;

	diag_router_send_msg_mask_to_all();

	/* Register the cmd's that need to be handled by the router */
	ret = diag_cmds_init();

	return ret;
}

int diag_router_exit()
{
	diag_cmds_exit();
	diag_masks_exit();

	return 0;
}
