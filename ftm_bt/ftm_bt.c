/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#include "diag_dbg.h"
#include "diag_peripheral_plugin.h"
#include "ftm.h"
#include "hdlc.h"
#include "mbuf.h"
#include "util.h"

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

unsigned int diag_dbg_mask = DIAG_DBG_NONE;

#define FTM_BT_DBG(fmt, arg...) diag_dbg(DIAG_DBG_PLUGIN, fmt, ##arg)
#define FTM_BT_DBG_DUMP(mask, prefix_str, buf, len) diag_dbg(DIAG_DBG_PLUGIN, mask, prefix_str, buf, len)

/* Reader thread handle */
pthread_t hci_cmd_thread_hdl;

/* rpmsg BT command channel to open */
#define  BT_RPMSG_CMD_CHANNEL "/dev/rpmsg/pronto/APPS_RIVA_BT_CMD"

#define DIAG_LOG_F      16

static int diag_app_fd = -1; // File descriptor for connection to diag apps
static int bt_fw_fd = -1; // File descriptor for connection to bt firmware

int diag_handle_ftm_bt(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len);

#define FTM_BT_CMD_CODE 4

static struct diag_cmd_registration_entry cmd_reg_entry = {
	.first_cmd = get_diag_cmd_subsys_ftm_key(FTM_BT_CMD_CODE),
	.last_cmd = get_diag_cmd_subsys_ftm_key(FTM_BT_CMD_CODE),
	.cb = &diag_handle_ftm_bt
};

static struct diag_cmd_registration_table cmd_reg_table = {
	.hdr = { .num_of_entries = 1 },
	.table = &cmd_reg_entry
};

struct diag_log_rsp {
	uint8_t cmd_code;
	uint8_t more;   	/* Indicates how many log entries, not including the one
						   returned with this packet, are queued up in the Mobile
						   Station.  If DIAG_DIAGVER >= 8, this should be set to 0 */
	uint16_t length;   	/* Indicates the length, in bytes, of the following log entry */
	uint8_t log_item[0]; 	/* Contains the log entry data. */
} __packed;

#define BT_HCI_CMD_PKT 		1
#define HCI_CMD_HDR_SIZE 	3
#define HC_VS_MAX_CMD_EVENT 256

#define BT_QSOC_READ_BD_ADDR_OPCODE        (0x1009)
#define OGF_INFO_PARAM			0x04
#define OCF_READ_BD_ADDR		0x0009
#define FTM_BT_CMD_NV_READ		0x0B
#define FTM_BT_CMD_NV_WRITE		0x0C
#define NV_BD_ADDR_I			0x01

#define BT_QSOC_EDL_CMD_CODE             (0x00)
#define BT_QSOC_MAX_NVM_CMD_SIZE     0x64  /* Maximum size config (NVM) cmd  */
#define BT_QSOC_MAX_BD_ADDRESS_SIZE  0x06  /* Length of BT Address */

#define FTM_BT_HCI_CMD_CODE 		0x1365
#define FTM_BT_HCI_EVENT_CODE 		0x1366

static int ftm_bt_send_log_packet(uint16_t type, void *buf, uint8_t len)
{
	struct diag_log_rsp *log_rsp_pkt;
	struct diag_log_item {
		uint16_t length;
		uint16_t log_code;
		uint64_t timestamp;
		uint8_t data[0];
	} __packed *log_item;
	size_t item_size = sizeof(*log_item) + len;
	size_t pkt_size = sizeof(*log_rsp_pkt) + item_size;
	int ret;
		
	log_rsp_pkt = malloc(pkt_size);
	if (log_rsp_pkt == NULL)
		return -errno;

	log_rsp_pkt->cmd_code = DIAG_LOG_F;
	log_rsp_pkt->more = 0; // this is single log packet
	log_rsp_pkt->length = (uint16_t)item_size;
	log_item = (struct diag_log_item *)log_rsp_pkt->log_item;
	log_item->length = (uint16_t)item_size;
	log_item->log_code = type;
	log_item->timestamp = (uint64_t)time(NULL);
	memcpy(&log_item->data, buf, len);

	ret = write(diag_app_fd, (uint8_t *)log_rsp_pkt, pkt_size);
	
	return ret;
}

static int ftm_bt_sendcmd (uint8_t *buf, uint8_t len)
{
	int n = 0;

	ftm_bt_send_log_packet(FTM_BT_HCI_CMD_CODE, buf, len);
	n = write(bt_fw_fd, buf, len);

	return n;
}

static int ftm_bt_hci_hal_read_bd_addr()
{
	uint16_t opcode = BT_QSOC_READ_BD_ADDR_OPCODE;
	uint8_t cmd[HC_VS_MAX_CMD_EVENT];
	int ret;
	uint8_t *msg = (&cmd[0]);
	uint8_t len = HCI_CMD_HDR_SIZE;

	cmd[0] = (uint8_t)(opcode & 0xFF);
	cmd[1] = (uint8_t)((opcode >> 8) & 0xFF);
	cmd[2] = 0;

	ret = ftm_bt_sendcmd(msg, len);
	if (ret < 0) {
		FTM_BT_DBG("Error->Send Header failed : %d\n", ret);
		ret = ftm_bt_send_log_packet(FTM_BT_HCI_CMD_CODE, NULL, 0);
	}

	return ret;
}

static int handle_incoming_packet(void *buf, uint8_t len)
{
	struct {
		uint8_t code;
		uint16_t rsvd;
		uint8_t ogf;
		uint8_t ocf;
		uint8_t cmd;
		struct {
			uint8_t type;
			uint8_t bd_addr[BT_QSOC_MAX_BD_ADDRESS_SIZE];
		} event_buf_nv_read_response;
	} __packed *pkt = buf;

	if ((pkt->code == 0x0E) &&
		(pkt->ocf == OCF_READ_BD_ADDR) && ((pkt->ogf >> 2) == OGF_INFO_PARAM)) {
		pkt->cmd = FTM_BT_CMD_NV_READ;
		pkt->event_buf_nv_read_response.type = NV_BD_ADDR_I;
		ftm_bt_send_log_packet(FTM_BT_HCI_EVENT_CODE, &pkt->event_buf_nv_read_response, sizeof(pkt->event_buf_nv_read_response));
	}

	return ftm_bt_send_log_packet(FTM_BT_HCI_EVENT_CODE, pkt, len);
}

/* FTM (BT) PKT Header */
struct ftm_bt_cmd_header {
	uint16_t cmd_id;            /* command id (required) */
	uint16_t cmd_data_len;      /* request pkt data length, excluding the diag and ftm headers
                             (optional, set to 0 if not used)*/
	uint16_t cmd_rsp_pkt_size;  /* rsp pkt size, size of response pkt if different then req pkt
                             (optional, set to 0 if not used)*/
} __packed;

/* Bluetooth FTM packet */
struct ftm_bt_pkt {
	struct diagpkt_subsys_header_type	diag_hdr;
	struct ftm_bt_cmd_header 			ftm_hdr;
	uint8_t								data[0];
} __packed;

static void *ftm_readerthread(void *ptr)
{
	fd_set readfds;
	int n = 0;
	uint8_t buf[1024];

	do {
		FD_ZERO(&readfds);
		FD_SET(bt_fw_fd, &readfds);
		select(bt_fw_fd + 1, &readfds, NULL, NULL, NULL);
		if (FD_ISSET(bt_fw_fd, &readfds)) {
			n = read(bt_fw_fd, buf, sizeof(buf));
			if (n > 0) {
				handle_incoming_packet(buf, n);
			} else if (n < 0) {
				warn("Can't read from bt diag channel\n");
				return 0;
			}
		}
	} while (bt_fw_fd >= 0);

	return 0;
}

int diag_handle_ftm_bt(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	int ret;
	uint8_t ind;
	struct ftm_bt_pkt *pkt = buf;

	if (pkt->ftm_hdr.cmd_id == BT_QSOC_EDL_CMD_CODE) {
		if ((pkt->data[1] == NV_BD_ADDR_I) && (pkt->data[0] == 0x0B)) {			/* BD_ADDRESS READ */
			ftm_bt_hci_hal_read_bd_addr();
		} else if ((pkt->data[1] == NV_BD_ADDR_I) && (pkt->data[0] == 0x0C)) { 	/* BD_ADDRESS WRITE */
			FTM_BT_DBG("write_bd_addr() Not supported\n");
		} else {
			ind = (pkt->data[0] == BT_HCI_CMD_PKT) ? 1 : 0;
			ret = ftm_bt_sendcmd((uint8_t *)(&pkt->data[ind]), pkt->ftm_hdr.cmd_data_len - ind);
			FTM_BT_DBG("wrote %d bytes to fd %d errno=%d\n", ret, bt_fw_fd, errno);
		}
	}

	ret = write(diag_app_fd, buf, len);
	FTM_BT_DBG("wrote %d bytes to fd %d\n", ret, diag_app_fd);

	return 0;
}

void diag_get_cmd_registration_table(struct diag_cmd_registration_table **tbl_ptr)
{
	*tbl_ptr = &cmd_reg_table;

	return;
}

int diag_set_pipe(int fd)
{
	diag_app_fd = fd;

	bt_fw_fd = open(BT_RPMSG_CMD_CHANNEL, O_RDWR);
	if (bt_fw_fd < 0) {
		warn("can't open bt rpmsg channel %s\n", BT_RPMSG_CMD_CHANNEL);
		return -1;
	}	
	
	/* Creating read thread which listens for various masks & pkt requests */
	pthread_create(&hci_cmd_thread_hdl, NULL, ftm_readerthread, NULL);

	return 0;
}

int diag_set_debug_level(int level)
{
	diag_dbg_mask = level;

	return 0;
}
