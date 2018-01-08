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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libudev.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "diag.h"
#include "diag_cntl.h"
#include "diag_dbg.h"
#include "hdlc.h"
#include "list.h"
#include "mbuf.h"
#include "peripheral.h"
#include "util.h"
#include "watch.h"

unsigned int diag_dbg_mask = DIAG_DBG_NONE;

struct list_head diag_cmds = LIST_INIT(diag_cmds);
struct list_head diag_clients = LIST_INIT(diag_clients);

static void usage(void)
{
	fprintf(stderr,
		"User space application for diag interface\n"
		"\n"
		"usage: diag [-hdgmsu]\n"
		"\n"
		"options:\n"
		"   -h   show this usage\n"
		"   -d   show more debug messages\n"
		"   -g   <gadget device name[#serial number]>\n"
		"   -m   <debug mask>\n"
		"   -s   <socket address[:port]>\n"
		"   -u   <uart device name[@baudrate]>\n"
	);

	exit(1);
}

int main(int argc, char **argv)
{
	struct diag_transport_config config;
	int ret;
	int c;
	bool debug = false;
	char *host_address = "";
	int host_port = DEFAULT_SOCKET_PORT;
	char *uartdev = "";
	int baudrate = DEFAULT_BAUD_RATE;
	char *gadgetdev = NULL;
	char *gadgetserial = NULL;
	char *token;

	if (argc == 1)
		usage();

	for (;;) {
		c = getopt(argc, argv, "m:hds:u:g:");
		if (c < 0)
			break;
		switch (c) {
		case 'd':
			debug = true;
			break;
		case 'm':
			diag_dbg_mask = strtoul(optarg, NULL, 16);
			break;
		case 's':
			host_address = strtok(strdup(optarg), ":");
			token = strtok(NULL, "");
			if (token)
				host_port = atoi(token);
			break;
		case 'u':
			uartdev = strtok(strdup(optarg), "@");
			token = strtok(NULL, "");
			if (token)
				baudrate = atoi(token);
			break;
		case 'g':
			gadgetdev = strtok(strdup(optarg), "#");
			gadgetserial = strtok(NULL, "");
			break;
		default:
		case 'h':
			usage();
			break;
		}
	}

	if (debug) {
		diag_dbg_mask = DIAG_DBG_ANY;
	}
	diag_dbg(DIAG_DBG_MAIN, "Debug mask is 0x%08X \n", diag_dbg_mask);

	config.hostname = host_address;
	config.port = host_port;

	config.uartname = uartdev;
	config.baudrate = baudrate;

	config.gadgetname = gadgetdev;
	config.gadgetserial = gadgetserial;

	ret = diag_transport_init(&config);
	if (ret < 0)
		err(1, "failed to connect to client");
	list_add(&diag_clients, &config.client->node);

	peripheral_init();
	diag_router_init();

	diag_dbg(DIAG_DBG_MAIN, "Starting loop\n");

	watch_run();

	diag_router_exit();
	peripheral_exit();

	list_del(&config.client->node);

	diag_transport_exit();

	return 0;
}
