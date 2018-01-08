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

struct diag_log_cmd_mask {
	uint32_t equip_id;
	uint32_t num_items;
	uint8_t mask[0];
}__packed;

#define DIAG_CMD_OP_LOG_DISABLE		0
#define DIAG_CMD_OP_GET_LOG_RANGE	1
#define DIAG_CMD_OP_SET_LOG_MASK	3
#define DIAG_CMD_OP_GET_LOG_MASK	4

#define DIAG_CMD_STATUS_SUCCESS					0
#define DIAG_CMD_STATUS_INVALID_EQUIPMENT_ID	1

#define DIAG_CMD_OP_GET_SSID_RANGE	1
#define DIAG_CMD_OP_GET_BUILD_MASK	2
#define DIAG_CMD_OP_GET_MSG_MASK	3
#define DIAG_CMD_OP_SET_MSG_MASK	4
#define DIAG_CMD_OP_SET_ALL_MSG_MASK	5

#define DIAG_CMD_MSG_STATUS_UNSUCCESSFUL		0
#define DIAG_CMD_MSG_STATUS_SUCCESSFUL			1

#define DIAG_CMD_EVENT_ERROR_CODE_OK			0
#define DIAG_CMD_EVENT_ERROR_CODE_FAIL			1

static int send_packet(struct diag_client *client, void *buf, size_t len, uint8_t transform)
{
	struct mbuf *resp_packet = create_packet(buf, len, transform);

	if (resp_packet == NULL) {
		warn("failed to create packet");

		return -1;
	}

	queue_push(&client->outq, resp_packet);

	return 0;
}

static int diag_router_handle_logging_configuration_response(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	struct diag_log_cmd_header {
		uint8_t cmd_code;
		uint8_t reserved[3];
		uint32_t operation;
	}__packed *request_header = buf;
	struct list_head *item;
	struct peripheral *peripheral;
	int ret;

	switch (request_header->operation) {
	case DIAG_CMD_OP_LOG_DISABLE: {
		struct {
			struct diag_log_cmd_header header;
			uint32_t status;
		} __packed resp;

		if (sizeof(*request_header) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		memcpy(&resp, request_header, sizeof(*request_header));
		diag_cmd_disable_log();
		resp.status = DIAG_CMD_STATUS_SUCCESS;

		list_for_each(item, &peripherals) {
			peripheral = container_of(item, struct peripheral, node);
			diag_cntl_send_log_mask(peripheral, 0); // equip_id is ignored
		}

		ret = send_packet(client, (uint8_t *)&resp, sizeof(resp), ENCODE);
		break;
	}
	case DIAG_CMD_OP_GET_LOG_RANGE: {
		struct {
			struct diag_log_cmd_header header;
			uint32_t status;
			uint32_t ranges[MAX_EQUIP_ID];
		} __packed resp;

		if (sizeof(*request_header) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		memcpy(&resp, request_header, sizeof(*request_header));
		diag_cmd_get_log_range(resp.ranges, MAX_EQUIP_ID);
		resp.status = DIAG_CMD_STATUS_SUCCESS;

		ret = send_packet(client, (uint8_t *)&resp, sizeof(resp), ENCODE);

		break;
	}
	case DIAG_CMD_OP_SET_LOG_MASK: {
		struct diag_log_cmd_mask *mask_to_set = (struct diag_log_cmd_mask*)(buf + sizeof(struct diag_log_cmd_header));
		struct {
			struct diag_log_cmd_header header;
			uint32_t status;
			struct diag_log_cmd_mask mask_structure;
		} __packed *resp;
		uint32_t resp_size = sizeof(*resp);
		uint32_t mask_size = sizeof(*mask_to_set) + LOG_ITEMS_TO_SIZE(mask_to_set->num_items);

		if (sizeof(*request_header) + mask_size != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		resp_size += mask_size;
		if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
			warn("Failed to allocate response packet\n");
			return -errno;
		}
		memcpy(resp, request_header, sizeof(*request_header));
		diag_dbg(DIAG_DBG_ROUTER, "Request: equip_id=%u num_items=%u\n", mask_to_set->equip_id, mask_to_set->num_items);
		diag_cmd_set_log_mask(mask_to_set->equip_id, &mask_to_set->num_items, mask_to_set->mask, &mask_size);
		memcpy(&resp->mask_structure, mask_to_set, mask_size); // num_items might have been capped!!!
		resp->status = DIAG_CMD_STATUS_SUCCESS;

		list_for_each(item, &peripherals) {
			peripheral = container_of(item, struct peripheral, node);
			diag_cntl_send_log_mask(peripheral, resp->mask_structure.equip_id);
		}

		ret = send_packet(client, resp, resp_size, ENCODE);
		free(resp);

		break;
	}
	case DIAG_CMD_OP_GET_LOG_MASK: {
		uint32_t *equip_id = (uint32_t *)(buf + sizeof(struct diag_log_cmd_header));
		struct get_log_response_resp {
			struct diag_log_cmd_header header;
			uint32_t status;
			struct diag_log_cmd_mask mask_structure;
		} __packed *resp;
		uint32_t num_items = 0;
		uint8_t *mask;
		uint32_t mask_size = 0;
		uint32_t resp_size = sizeof(*resp);

		if (sizeof(*request_header) + sizeof(*equip_id) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		if (diag_cmd_get_log_mask(*equip_id, &num_items, &mask, &mask_size) == 0) {
			resp_size += mask_size;
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			memcpy(resp, request_header, sizeof(*request_header));
			resp->mask_structure.equip_id = *equip_id;
			resp->mask_structure.num_items = num_items;
			if (mask != NULL) {
				memcpy(&resp->mask_structure.mask, mask, mask_size);
				free(mask);
			}
			resp->status = DIAG_CMD_STATUS_SUCCESS;
		} else {
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			memcpy(resp, request_header, sizeof(*request_header));
			resp->mask_structure.equip_id = *equip_id;
			resp->mask_structure.num_items = num_items;
			resp->status = DIAG_CMD_STATUS_INVALID_EQUIPMENT_ID;
		}

		list_for_each(item, &peripherals) {
			peripheral = container_of(item, struct peripheral, node);
			diag_cntl_send_log_mask(peripheral, resp->mask_structure.equip_id);
		}

		ret = send_packet(client, resp, resp_size, ENCODE);
		free(resp);

		break;
	}
	default:
		warn("Unrecognized operation %d!!!", request_header->operation);
		ret = diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_PARAMS);
		break;
	}

	return ret;
}

static int diag_router_handle_extended_message_configuration_response(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	struct diag_msg_cmd_header {
		uint8_t cmd_code;
		uint8_t operation;
	}__packed *request_header = buf;
	struct list_head *item;
	struct peripheral *peripheral;
	int ret;

	switch (request_header->operation) {
	case DIAG_CMD_OP_GET_SSID_RANGE: {
		struct {
			struct diag_msg_cmd_header header;
			uint8_t status;
			uint8_t reserved;
			uint32_t range_cnt;
			struct diag_ssid_range_t ranges[];
		} __packed *resp;
		uint32_t resp_size = sizeof(*resp);
		uint32_t count = 0;
		struct diag_ssid_range_t *ranges = NULL;
		uint32_t ranges_size = 0;

		if (sizeof(*request_header) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		diag_cmd_get_ssid_range(&count, &ranges);
		ranges_size = count * sizeof(*ranges);
		resp_size += ranges_size;
		if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
			warn("Failed to allocate response packet\n");
			return -errno;
		}
		memcpy(resp, request_header, sizeof(*request_header));
		resp->range_cnt = count;
		if (ranges != NULL) {
			memcpy(resp->ranges, ranges, ranges_size);
			free(ranges);
		}
		resp->status = DIAG_CMD_MSG_STATUS_SUCCESSFUL;

		ret = send_packet(client, (uint8_t *)resp, resp_size, ENCODE);
		free(resp);

		break;
	}
	case DIAG_CMD_OP_GET_BUILD_MASK: {
		struct diag_ssid_range_t *range = (struct diag_ssid_range_t *)(buf + sizeof(struct diag_msg_cmd_header));
		struct {
			struct diag_msg_cmd_header header;
			uint8_t status;
			uint8_t reserved;
			uint32_t bld_masks[];
		} __packed *resp;
		uint32_t resp_size = sizeof(*resp);
		uint32_t *masks = NULL;
		uint32_t masks_size = 0;

		if (sizeof(*request_header) + sizeof(*range) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		if (diag_cmd_get_build_mask(range, &masks) == 0) {
			masks_size = MSG_RANGE_TO_SIZE(*range);
			resp_size += masks_size;
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			memcpy(resp, request_header, sizeof(*request_header));
			if (masks != NULL) {
				memcpy(resp->bld_masks, masks, masks_size);
				free(masks);
			}
			resp->status = DIAG_CMD_MSG_STATUS_SUCCESSFUL;
		} else {
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			memcpy(resp, request_header, sizeof(*request_header));
			resp->status = DIAG_CMD_MSG_STATUS_UNSUCCESSFUL;
		}

		ret = send_packet(client, (uint8_t *)resp, resp_size, ENCODE);
		free(resp);

		break;
	}
	case DIAG_CMD_OP_GET_MSG_MASK: {
		struct diag_ssid_range_t *range = buf + sizeof(struct diag_msg_cmd_header);
		struct {
			struct diag_msg_cmd_header header;
			uint8_t status;
			uint8_t rsvd;
			uint32_t rt_masks[];
		} __packed *resp;
		uint32_t resp_size = sizeof(*resp);
		uint32_t *masks = NULL;
		uint32_t masks_size = 0;

		if (sizeof(*request_header) + sizeof(*range) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		if (diag_cmd_get_msg_mask(range, &masks) == 0) {
			masks_size = MSG_RANGE_TO_SIZE(*range);
			resp_size += masks_size;
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			memcpy(resp, request_header, sizeof(*request_header));
			if (masks != NULL) {
				memcpy(resp->rt_masks, masks, masks_size);
				free(masks);
			}
			resp->status = DIAG_CMD_MSG_STATUS_SUCCESSFUL;
		} else {
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			memcpy(resp, request_header, sizeof(*request_header));
			resp->status = DIAG_CMD_MSG_STATUS_UNSUCCESSFUL;
		}

		ret = send_packet(client, resp, resp_size, ENCODE);
		free(resp);

		break;
	}
	case DIAG_CMD_OP_SET_MSG_MASK: {
		struct {
			struct diag_msg_cmd_header header;
			struct diag_ssid_range_t range;
			uint8_t rsvd;
			uint32_t masks[];
		} __packed *req = buf;
		struct {
			struct diag_msg_cmd_header header;
			struct diag_ssid_range_t range;
			uint8_t status;
			uint8_t rsvd;
			uint32_t rt_masks[0];
		} __packed *resp;
		uint32_t resp_size = sizeof(*resp);
		uint32_t masks_size = MSG_RANGE_TO_SIZE(req->range);

		if (sizeof(*req) + masks_size != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		if (diag_cmd_set_msg_mask(req->range, req->masks) == 0) {
			resp_size += masks_size;
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			resp->header = req->header;
			resp->range = req->range;
			resp->rsvd = req->rsvd;
			if (req->masks != NULL) {
				memcpy(resp->rt_masks, req->masks, masks_size);
			}
			resp->status = DIAG_CMD_MSG_STATUS_SUCCESSFUL;

			list_for_each(item, &peripherals) {
				peripheral = container_of(item, struct peripheral, node);
				diag_cntl_send_msg_mask(peripheral, &resp->range);
			}
		} else {
			if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
				warn("Failed to allocate response packet\n");
				return -errno;
			}
			resp->header = req->header;
			resp->range = req->range;
			resp->rsvd = req->rsvd;
			resp->status = DIAG_CMD_MSG_STATUS_UNSUCCESSFUL;
		}

		ret = send_packet(client, (uint8_t *)resp, resp_size, ENCODE);
		free(resp);

		break;
	}
	case DIAG_CMD_OP_SET_ALL_MSG_MASK: {
		struct {
			struct diag_msg_cmd_header header;
			uint8_t rsvd;
			uint32_t mask;
		} __packed *req = buf;
		struct {
			struct diag_msg_cmd_header header;
			uint8_t status;
			uint8_t rsvd;
			uint32_t rt_mask;
		} __packed resp;

		if (sizeof(*req) != len) {
			return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
		}

		diag_cmd_set_all_msg_mask(req->mask);
		resp.header = req->header;
		resp.rsvd = req->rsvd;
		resp.rt_mask = req->mask;
		resp.status = DIAG_CMD_MSG_STATUS_SUCCESSFUL;

		list_for_each(item, &peripherals) {
			peripheral = container_of(item, struct peripheral, node);
			diag_cntl_send_msg_mask(peripheral, NULL); // range is ignored
		}

		ret = send_packet(client, (uint8_t *)&resp, sizeof(resp), ENCODE);
		break;
	}
	default:
		warn("Unrecognized operation %d!!!", request_header->operation);
		ret = diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_PARAMS);
		break;
	}

	return ret;
}

static int diag_router_handle_event_get_mask_response(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	struct {
		uint8_t cmd_code;
		uint8_t pad;
		uint16_t reserved;
	} __packed *req = buf;
	struct {
		uint8_t cmd_code;
		uint8_t error_code;
		uint16_t reserved;
		uint16_t num_bits;
		uint8_t mask[0];
	} __packed *resp;
	uint32_t resp_size = sizeof(*resp);
	uint16_t num_bits = event_max_num_bits;
	uint16_t mask_size = 0;
	uint8_t *mask = NULL;
	int ret;

	if (sizeof(*req) != len) {
		return diag_rsp_bad_command(client, buf, len, DIAG_CMD_RSP_BAD_LENGTH);
	}

	if (diag_cmd_get_event_mask(num_bits, &mask) == 0) {
		mask_size = EVENT_COUNT_TO_BYTES(num_bits);
		resp_size += mask_size;
		if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
			warn("Failed to allocate response packet\n");
			return -errno;
		}
		resp->cmd_code = req->cmd_code;
		resp->reserved = req->reserved;
		resp->num_bits = num_bits;
		if (mask != NULL) {
			memcpy(&resp->mask, mask, mask_size);
			free(mask);
		}
		resp->error_code = DIAG_CMD_EVENT_ERROR_CODE_OK;
	} else {
		if (posix_memalign((void **)&resp, PACKET_ALLOC_ALIGNMENT, resp_size)) {
			warn("Failed to allocate response packet\n");
			return -errno;
		}
		resp->cmd_code = req->cmd_code;
		resp->reserved = req->reserved;
		resp->num_bits = 0;
		resp->error_code = DIAG_CMD_EVENT_ERROR_CODE_FAIL;
	}

	ret = send_packet(client, (uint8_t *)resp, resp_size, ENCODE);
	free(resp);

	return ret;
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

	register_diag_cmd(DIAG_CMD_LOGGING_CONFIGURATION_KEY, diag_router_handle_logging_configuration_response, &common_cmds);
	register_diag_cmd(DIAG_CMD_EXTENDED_MESSAGE_CONFIGURATION_KEY, diag_router_handle_extended_message_configuration_response, &common_cmds);
	register_diag_cmd(DIAG_CMD_GET_MASK_KEY, diag_router_handle_event_get_mask_response, &common_cmds);

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
