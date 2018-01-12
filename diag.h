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

#define BIT(x) (1 << (x))

#define DIAG_FEATURE_FEATURE_MASK_SUPPORT	BIT(0)
#define DIAG_FEATURE_LOG_ON_DEMAND_APPS		BIT(2)
#define DIAG_FEATURE_REQ_RSP_SUPPORT		BIT(4)
#define DIAG_FEATURE_APPS_HDLC_ENCODE		BIT(6)
#define DIAG_FEATURE_STM			BIT(9)
#define DIAG_FEATURE_PERIPHERAL_BUFFERING	BIT(10)
#define DIAG_FEATURE_MASK_CENTRALIZATION	BIT(11)
#define DIAG_FEATURE_SOCKETS_ENABLED		BIT(13)

#define DIAG_CMD_SUBSYS_DISPATCH       75

#define DIAG_CMD_RSP_BAD_COMMAND			0x13

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

#define APPS_BUF_SIZE 4096

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
#endif // __DIAG_H__
