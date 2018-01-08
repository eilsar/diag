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
#ifndef __DIAG_H__
#define __DIAG_H__

#include <stdint.h>

#include "list.h"
#include "mbuf.h"
#include "peripheral.h"

#define PACKET_ALLOC_ALIGNMENT sizeof(void *)

#define BIT(x) (1 << (x))

#define DIAG_FEATURE_FEATURE_MASK_SUPPORT			BIT(0)
#define DIAG_FEATURE_DIAG_MASTER_SETS_COMMON_MASK	BIT(1)
#define DIAG_FEATURE_LOG_ON_DEMAND_APPS				BIT(2)
#define DIAG_FEATURE_DIAG_VERSION_RSP_ON_MASTER		BIT(3)
#define DIAG_FEATURE_REQ_RSP_SUPPORT				BIT(4)
#define DIAG_FEATURE_DIAG_PRESET_MASKS				BIT(5)
#define DIAG_FEATURE_APPS_HDLC_ENCODE				BIT(6)
#define DIAG_FEATURE_STM							BIT(9)
#define DIAG_FEATURE_PERIPHERAL_BUFFERING			BIT(10)
#define DIAG_FEATURE_MASK_CENTRALIZATION			BIT(11)
#define DIAG_FEATURE_SOCKETS_ENABLED				BIT(13)

#define DIAG_CMD_RSP_BAD_COMMAND			0x13
#define DIAG_CMD_RSP_BAD_PARAMS				0x14
#define DIAG_CMD_RSP_BAD_LENGTH				0x15

#define get_diag_cmd_key(cmd_id) \
	(0xffff0000 | (0xffff & (cmd_id)))
#define get_diag_cmd_subsys_dispatch_key(cmd_id, subsys_id, subsys_cmd) \
	(((0xff & (cmd_id)) << 24) | ((0xff & (subsys_id)) << 16) | ((0xffff & (subsys_cmd))))

#define DIAG_CMD_SUBSYS_DISPATCH       				75
#define DIAG_CMD_SUBSYS_DISPATCH_V2					128

#define DIAG_CMD_KEEP_ALIVE_KEY get_diag_cmd_subsys_dispatch_key(DIAG_CMD_SUBSYS_DISPATCH, 50, 0x0003)

#define MOBILE_MODEL_NUMBER							0
#define MOBILE_SOFTWARE_REVISION					"OE"
#define MOBILE_MODEL_STRING							"DB410C"
#define MSM_REVISION_NUMBER							2
#define DIAG_CMD_EXTENDED_BUILD_ID					124
#define DIAG_CMD_EXTENDED_BUILD_ID_KEY get_diag_cmd_key(DIAG_CMD_EXTENDED_BUILD_ID)

#define DIAG_PROTOCOL_VERSION_NUMBER 				2
#define DIAG_CMD_DIAG_VERSION_ID					28
#define DIAG_CMD_DIAG_VERSION_KEY get_diag_cmd_key(DIAG_CMD_DIAG_VERSION_ID)

#define DIAG_CMD_LOGGING_CONFIGURATION 				0x73
#define DIAG_CMD_LOGGING_CONFIGURATION_KEY get_diag_cmd_key(DIAG_CMD_LOGGING_CONFIGURATION)
#define DIAG_CMD_EXTENDED_MESSAGE_CONFIGURATION 	0x7d
#define DIAG_CMD_EXTENDED_MESSAGE_CONFIGURATION_KEY get_diag_cmd_key(DIAG_CMD_EXTENDED_MESSAGE_CONFIGURATION)
#define DIAG_CMD_GET_MASK 							0x81
#define DIAG_CMD_GET_MASK_KEY get_diag_cmd_key(DIAG_CMD_GET_MASK)
#define DIAG_CMD_SET_MASK 							0x82
#define DIAG_CMD_SET_MASK_KEY get_diag_cmd_key(DIAG_CMD_SET_MASK)

struct diag_client {
	const char *name;
	int in_fd;
	int out_fd;
	struct list_head outq;

	struct list_head node;
};

extern struct list_head diag_clients;

struct diag_cmd {
	unsigned int first;
	unsigned int last;
	struct peripheral *peripheral;
	int(*cb)(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len);

	struct list_head node;
};

extern struct list_head diag_cmds;

int diag_cmd_recv(int fd, void *data);
int diag_data_recv(int fd, void *data);

#define APPS_BUF_SIZE 16384

int diag_router_handle_incoming(struct diag_client *client, void *buf, size_t len);

struct diag_transport_config {
	const char *hostname;
	unsigned short port;
	const char *uartname;
	unsigned int baudrate;
	const char* gadgetname;
	const char* gadgetserial;
	struct diag_client *client;
};

#define DEFAULT_SOCKET_PORT 2500
#define DEFAULT_BAUD_RATE 115200

int diag_transport_init(struct diag_transport_config *config);
int diag_transport_exit();

int diag_cmd_forward_to_peripheral(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len);

int diag_router_init();
int diag_router_exit();
#endif // __DIAG_H__
