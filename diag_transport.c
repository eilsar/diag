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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "diag.h"
#include "diag_dbg.h"
#include "hdlc.h"

int diag_sock_connect(const char *hostname, unsigned short port)
{
	struct sockaddr_in addr = {0};
	int ret;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	addr.sin_family = AF_INET;
	inet_aton(hostname, &addr.sin_addr);
	addr.sin_port = htons(port);

	ret = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
		return -errno;

	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (ret < 0)
		return -errno;

	diag_info("Connected to %s:%d\n", hostname, port);

	return fd;
}

int diag_sock_recv(int fd, void* data)
{
	struct diag_client *client = (struct diag_client *)data;
	uint8_t buf[APPS_BUF_SIZE] = { 0 };
	uint8_t *ptr;
	uint8_t *msg;
	size_t msglen;
	size_t len;
	ssize_t n;

	n = read(client->fd, buf, sizeof(buf));
	if ((n < 0) && (errno != EAGAIN)) {
		warn("Failed to read from fd=%d\n", client->fd);
		return n;
	}

	ptr = buf;
	len = n;

	for ( ;; ) {
		msg = hdlc_decode_one(&ptr, &len, &msglen);
		if (!msg)
			break;

		diag_dbg_dump(DIAG_DBG_TRANSPORT_DUMP, "Packet: ", msg, msglen);
		diag_client_handle_command(client, msg, msglen);
	}

	return 0;
}
