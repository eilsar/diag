/*
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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

static int hdlc_enqueue(struct list_head *queue, uint8_t *msg, size_t msglen)
{
	struct mbuf *mbuf;
	uint8_t *outbuf;
	size_t outlen;
	void *ptr;

	outbuf = hdlc_encode(msg, msglen, &outlen);
	if (!outbuf)
		err(1, "failed to allocate hdlc destination buffer");

	mbuf = mbuf_alloc(outlen);
	ptr = mbuf_put(mbuf, outlen);
	memcpy(ptr, outbuf, outlen);

	list_add(queue, &mbuf->node);

	return 0;
}

void queue_push(struct list_head *queue, uint8_t *msg, size_t msglen)
{
	struct mbuf *mbuf;
	void *ptr;

	mbuf = mbuf_alloc(msglen);
	ptr = mbuf_put(mbuf, msglen);
	memcpy(ptr, msg, msglen);

	list_add(queue, &mbuf->node);
}

int diag_data_recv(int fd, void *data)
{
	struct peripheral *peripheral = data;
	struct diag_client *client;
	struct list_head *item;
	uint8_t buf[4096];
	uint8_t *ptr;
	uint8_t *msg;
	size_t msglen;
	size_t len;
	ssize_t n;

	for (;;) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno != EAGAIN) {
				warn("failed to read from data channel");
				peripheral_close(peripheral);
			}

			break;
		}

		ptr = buf;
		len = n;
		for (;;) {
			if (peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE) {
				msg = ptr;
				msglen = len;
			} else {
				msg = hdlc_decode_one(&ptr, &len, &msglen);
				if (!msg)
					break;
			}

			list_for_each(item, &diag_clients) {
				client = container_of(item, struct diag_client, node);

				queue_push(&client->outq, msg, msglen);
			}

			if (peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE)
				break;
		}
	}

	return 0;
}

static int diag_sock_connect(const char *hostname, unsigned short port)
{
	struct sockaddr_in addr;
	struct hostent *host;
	int ret;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	host = gethostbyname(hostname);
	if (!host)
		return -errno;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	bcopy(host->h_addr, &addr.sin_addr.s_addr, host->h_length);
	addr.sin_port = htons(port);

	ret = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		return -errno;

	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (ret < 0)
		return -errno;

	printf("Connected to %s:%d\n", hostname, port);

	return fd;
}

static int diag_cmd_dispatch(uint8_t *ptr, size_t len)
{
	struct peripheral *peripheral;
	struct list_head *item;
	struct diag_cmd *dc;
	uint8_t *outbuf;
	size_t outlen;
	unsigned int key;
	int handled = 0;

	outbuf = hdlc_encode(ptr, len, &outlen);
	if (!outbuf)
		err(1, "failed to allocate hdlc destination buffer");

	if (ptr[0] == DIAG_CMD_SUBSYS_DISPATCH)
		key = ptr[0] << 24 | ptr[1] << 16 | ptr[3] << 8 | ptr[2];
	else
		key = 0xff << 24 | 0xff << 16 | ptr[0];

	list_for_each(item, &diag_cmds) {
		dc = container_of(item, struct diag_cmd, node);
		if (key < dc->first || key > dc->last)
			continue;

		peripheral = dc->peripheral;

		if (peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE)
			queue_push(&peripheral->dataq, ptr, len);
		else
			hdlc_enqueue(&dc->peripheral->dataq, ptr, len);

		handled++;
	}

	free(outbuf);

	return handled ? 0 : -ENOENT;
}

static void diag_rsp_bad_command(struct diag_client *client,
				 uint8_t *msg, size_t len)
{
	uint8_t *buf;

	buf = malloc(len + 1);
	if (!buf)
		err(1, "failed to allocate error buffer");

	buf[0] = 0x13;
	memcpy(buf + 1, msg, len);

	hdlc_enqueue(&client->outq, buf, len + 1);

	free(buf);
}

static int diag_sock_recv(int fd, void *data)
{
	struct diag_client *client = data;
	uint8_t buf[4096];
	uint8_t *ptr;
	uint8_t *msg;
	size_t msglen;
	size_t len;
	ssize_t n;
	int ret;

	n = read(fd, buf, sizeof(buf));
	if (n < 0)
		return n;

	ptr = buf;
	len = n;
	for (;;) {
		msg = hdlc_decode_one(&ptr, &len, &msglen);
		if (!msg)
			break;

		ret = diag_cmd_dispatch(msg, msglen);
		if (ret < 0)
			diag_rsp_bad_command(client, msg, msglen);
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"User space application for diag interface\n"
		"\n"
		"usage: diag [-hdms]\n"
		"\n"
		"options:\n"
		"   -h   show this usage\n"
		"   -d   show more debug messages\n"
		"   -m   <debug mask>\n"
		"   -s   <socket address[:port]>\n"
	);
	exit(1);
}

int main(int argc, char **argv)
{
	struct diag_client *client;
	int ret;
	int c;
	bool debug = false;
	char *host_address = "";
	int host_port = DEFAULT_SOCKET_PORT;
	char *token;

	for (;;) {
		c = getopt(argc, argv, "m:hds:");
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

	client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	ret = diag_sock_connect(host_address, host_port);
	if (ret < 0)
		err(1, "failed to connect to client");
	client->fd = ret;
	client->name = "DIAG CLIENT";

	watch_add_readfd(ret, diag_sock_recv, client);
	watch_add_writeq(client->fd, &client->outq);
	list_add(&diag_clients, &client->node);

	diag_dbg(DIAG_DBG_MAIN, "Opened client %s with fd=%d\n", client->name, client->fd);

	peripheral_init();

	watch_run();

	return 0;
}
