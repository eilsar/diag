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
#include <sys/time.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "diag.h"
#include "diag_dbg.h"
#include "diag_transport.h"
#include "hdlc.h"
#include "util.h"
#include "watch.h"

static struct diag_transport_config *config = NULL;
static uint8_t g_buf[APPS_BUF_SIZE] = { 0 };
static size_t g_offset = 0;

static int diag_transport_recv(int fd, void* data)
{
	struct diag_client *client = data;
	void *buf = g_buf + g_offset, *curr_pkt_ptr = g_buf, *next_pkt_ptr;
	size_t buf_len = sizeof(g_buf) - g_offset, pkt_len = 0;
	ssize_t n;
	struct mbuf *packet;

	while (curr_pkt_ptr == g_buf) { // loop till we get at least one full packet
		n = read(client->in_fd, buf, buf_len);
		if (n <= 0) {
			if (errno != EAGAIN) {
				warn("Failed to read from fd=%d\n", client->in_fd);
				return -errno;
			} else {
				continue;
			}
		}

		buf_len -= n;
		g_offset += n;

		for ( ;; ) {
			next_pkt_ptr = memchr(curr_pkt_ptr, 0x7e, n); // look for end of packet char
			if (next_pkt_ptr == NULL) {
				buf = g_buf + g_offset;
				pkt_len = buf - curr_pkt_ptr;
				break; // need to read some more to get the end of packet char
			}
			next_pkt_ptr++;

			pkt_len = next_pkt_ptr - curr_pkt_ptr;
			n -= pkt_len;
			diag_dbg_dump(DIAG_DBG_TRANSPORT_DUMP, "Received:\n", curr_pkt_ptr, pkt_len);
			packet = create_packet(curr_pkt_ptr, pkt_len, client->encoded ? DECODE : KEEP_AS_IS);
			curr_pkt_ptr = next_pkt_ptr;
			if (packet == NULL)
				return -ENOMEM;
			diag_router_handle_incoming(client, packet->data, packet->offset);
			free(packet);
		}
	}

	g_offset = pkt_len;

	// save part of packet if any for next call
	if (pkt_len) {
		memcpy(g_buf, curr_pkt_ptr, pkt_len);
		memset(g_buf + g_offset, 0, sizeof(g_buf) - g_offset);
	}

	return 0;
}

int diag_transport_send(struct diag_client *client, void *buf, size_t len, bool encoded)
{
	uint8_t transform = KEEP_AS_IS;
	struct mbuf *resp_packet;

	if (client == NULL) {
		client = config->client;
	}

	if (client->encoded && !encoded)
		transform = ENCODE;
	else if (!client->encoded && encoded)
		transform = DECODE;

	resp_packet = create_packet(buf, len, transform);

	if (resp_packet == NULL) {
		warn("failed to create packet");

		return -1;
	}

	diag_dbg_dump(DIAG_DBG_TRANSPORT_DUMP, "Sending:\n", resp_packet->data, resp_packet->offset);
	queue_push(&client->outq, resp_packet);

	return 0;
}

int diag_transport_init(struct diag_transport_config *dtc)
{
	int ret;

	config = dtc;
	config->client = malloc(sizeof(struct diag_client));
	memset(config->client, 0, sizeof(struct diag_client));

	config->client->encoded = DIAG_CLIENT_ENCODED;

	if (config->hostname)
		ret = diag_sock_connect(config->hostname, config->port);
	else if (config->uartname)
		ret = diag_uart_connect(config->uartname, config->baudrate);
	else // if (config->gadgetname) // uncomment to not make USB default
		ret = diag_usb_connect(config->gadgetname, config->gadgetserial, &config->client->in_fd, &config->client->out_fd, "", "");
	if (ret < 0) {
		warn("failed to connect to client");
		free(config->client);
		config->client = NULL;
		return ret;
	}

	if (config->hostname || config->uartname) {
		config->client->in_fd = config->client->out_fd = ret;
	}

	config->client->name = strdup("HOST PC");
	diag_dbg(DIAG_DBG_TRANSPORT, "Established in_fd=%d, out_fd=%d, name=%s\n",
			config->client->in_fd, config->client->out_fd, config->client->name);

	watch_add_readfd(config->client->in_fd, diag_transport_recv, config->client);
	watch_add_writeq(config->client->out_fd, &config->client->outq);

	return 0;
}

int diag_transport_exit()
{
	watch_remove_fd(config->client->in_fd);
	watch_remove_fd(config->client->out_fd);
	free(config->client);
	config->client = NULL;
	config = NULL;

	return 0;
}
