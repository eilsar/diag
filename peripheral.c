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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "diag_dbg.h"
#include "diag_cntl.h"
#include "list.h"
#include "peripheral.h"
#include "util.h"
#include "watch.h"

struct list_head devnodes = LIST_INIT(devnodes);
struct list_head peripherals = LIST_INIT(peripherals);

struct devnode {
	char *devnode;
	char *name;
	char *rproc;

	struct list_head node;
};

static struct devnode *devnode_get(const char *devnode)
{
	struct list_head *item;
	struct devnode *node;

	list_for_each(item, &devnodes) {
		node = container_of(item, struct devnode, node);
		if (strcmp(node->devnode, devnode) == 0)
			return node;
	}

	return NULL;
}

static int devnode_open(const char *rproc, const char *name)
{
	struct list_head *item;
	struct devnode *node;

	list_for_each(item, &devnodes) {
		node = container_of(item, struct devnode, node);
		if (strcmp(node->rproc, rproc) == 0 &&
		    strcmp(node->name, name) == 0)
			return open(node->devnode, O_RDWR);
	}

	return -1;
}

static void devnode_add(const char *devnode, const char *name, const char *rproc)
{
	struct devnode *node;

	node = devnode_get(devnode);
	if (node) {
		warnx("node already in list");
		return;
	}

	node = malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));

	node->devnode = strdup(devnode);
	node->name = strdup(name);
	node->rproc = strdup(rproc);

	list_add(&devnodes, &node->node);

	diag_dbg(DIAG_DBG_PERIPHERAL, "Added device node (%s %s %s)\n", node->devnode, node->rproc, node->name);
}

static void devnode_remove(const char *devnode)
{
	struct devnode *node;

	node = devnode_get(devnode);
	if (!node)
		return;

	list_del(&node->node);

	diag_dbg(DIAG_DBG_PERIPHERAL, "Removed device node (%s %s %s)\n", node->devnode, node->rproc, node->name);

	free(node->name);
	free(node->devnode);
	free(node->rproc);
}

static const char *peripheral_udev_get_name(struct udev_device *dev)
{
	return udev_device_get_sysattr_value(dev, "name");
}

static const char *peripheral_udev_get_remoteproc(struct udev_device *dev)
{
	struct udev_device *parent;
	const char *p;

	parent = udev_device_get_parent(dev);
	if (!parent)
		return NULL;

	p = udev_device_get_sysattr_value(parent, "rpmsg_name");
	if (p)
		return p;

	return peripheral_udev_get_remoteproc(parent);
}

static int peripheral_udev_update(int fd, void *data);

static int peripheral_udev_init(void)
{
	struct udev_list_entry *devices;
	struct udev_list_entry *entry;
	struct udev_enumerate *enu;
	struct udev_monitor *mon;
	struct udev_device *dev;
	struct udev *udev;
	const char *devnode;
	const char *path;
	const char *rproc;
	const char *name;
	int fd;

	udev = udev_new();
	if (!udev)
		err(1, "failed to initialize libudev");

	mon = udev_monitor_new_from_netlink(udev, "udev");
	udev_monitor_filter_add_match_subsystem_devtype(mon, "rpmsg", NULL);
	udev_monitor_enable_receiving(mon);

	fd = udev_monitor_get_fd(mon);

	enu = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enu, "rpmsg");
	udev_enumerate_scan_devices(enu);

	devices = udev_enumerate_get_list_entry(enu);
	udev_list_entry_foreach(entry, devices) {
		path = udev_list_entry_get_name(entry);
		dev = udev_device_new_from_syspath(udev, path);

		devnode = udev_device_get_devnode(dev);
		name = peripheral_udev_get_name(dev);
		rproc = peripheral_udev_get_remoteproc(dev);

		if (devnode && name && rproc) {
			devnode_add(devnode, name, rproc);
		}

		udev_device_unref(dev);
	}

	watch_add_readfd(fd, peripheral_udev_update, mon);

	return 0;
}

void peripheral_close(struct peripheral *peripheral)
{
	int i;
	struct channel *ch;

	if (peripheral == NULL)
		return;

	diag_cntl_close(peripheral);
	diag_dbg(DIAG_DBG_PERIPHERAL, "Closing each channel\n");
	for (i = peripheral_ch_type_data; i < MAX_NUM_OF_CH; i++) {
		ch = &peripheral->channels[i];
		if (ch->name && ch->fd >= 0) {
			watch_remove_fd(ch->fd);
			diag_dbg(DIAG_DBG_PERIPHERAL, "Closing channel %s fd = %d\n", ch->name, ch->fd);
			close(ch->fd);
			ch->fd = -1;
		}
	}
}

static int peripheral_cmd_recv(int fd, void *data)
{
	struct peripheral *peripheral = data;
	uint8_t buf[APPS_BUF_SIZE];
	size_t len;
	ssize_t n;
	uint8_t transform;

	diag_dbg(DIAG_DBG_PERIPHERAL, "Reading response from %s\n", peripheral->name);
	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		if (errno != EAGAIN) {
			warn("failed to read from cmd channel");
			peripheral_close(peripheral);
			return -1;
		}
		return 0;
	}

	len = n;
	transform = peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE ? KEEP_AS_IS : ENCODE;

	return diag_transport_send(NULL, buf, len, transform);
}

static int peripheral_data_recv(int fd, void *data)
{
	struct peripheral *peripheral = data;
	uint8_t buf[APPS_BUF_SIZE];
	size_t len;
	ssize_t n;
	uint8_t transform;

	diag_dbg(DIAG_DBG_PERIPHERAL, "Reading response from %s\n", peripheral->name);
	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		if (errno != EAGAIN) {
			warn("failed to read from data channel");
			peripheral_close(peripheral);
			return -1;
		}
		return 0;
	}

	len = n;
	transform = peripheral->features & DIAG_FEATURE_APPS_HDLC_ENCODE ? KEEP_AS_IS : ENCODE;

	return diag_transport_send(NULL, buf, len, transform);
}

static void peripheral_open(struct peripheral *peripheral)
{
	int i;
	int fd = -1;
	struct channel *ch;
	int ret;

	if (peripheral == NULL)
		return;

	for (i = peripheral_ch_type_data; i < MAX_NUM_OF_CH; i++) {
		ch = &peripheral->channels[i];
		if (ch->name && ch->fd < 0) {
			fd = devnode_open(peripheral->name, ch->name);
			if (fd >= 0) {
				ch->fd = fd;
				diag_dbg(DIAG_DBG_PERIPHERAL, "Opened on device %s channel %s with fd = %d\n", peripheral->name, ch->name, ch->fd);
				switch (i) {
				case peripheral_ch_type_data:
					ret = fcntl(ch->fd, F_SETFL, O_NONBLOCK);
					if (ret < 0)
						warn("failed to turn %s non blocking", ch->name);
					watch_add_writeq(ch->fd, &ch->queue);
					watch_add_readfd(ch->fd, peripheral_data_recv, peripheral);
					break;
				case peripheral_ch_type_ctrl:
					watch_add_writeq(ch->fd, &ch->queue);
					watch_add_readfd(ch->fd, diag_cntl_recv, peripheral);
					break;
				case peripheral_ch_type_cmd:
					watch_add_writeq(ch->fd, &ch->queue);
					watch_add_readfd(ch->fd, peripheral_cmd_recv, peripheral);
					break;
				default:
					break;
				}
			} else {
				warn("failed to open %s channel closing peripheral %s", ch->name, peripheral->name);
				peripheral_close(peripheral);
				break;
			}
		}
	}

	return;
}

static struct peripheral *peripheral_get_by_name(const char* name)
{
	struct list_head *item;
	struct peripheral *peripheral;

	list_for_each(item, &peripherals) {
		peripheral = container_of(item, struct peripheral, node);
		if (strcmp(peripheral->name, name) == 0) {
			return peripheral;
		}
	}

	return NULL;
}

static struct peripheral *peripheral_create(const char *name)
{
	struct peripheral *peripheral;
	int i;
	struct channel *ch;

	peripheral = peripheral_get_by_name(name);
	if (peripheral != NULL) {
		warn("%s device created already!\n", name);
		return peripheral;
	}

	peripheral = malloc(sizeof(*peripheral));
	memset(peripheral, 0, sizeof(*peripheral));

	for (i = peripheral_ch_type_data; i < MAX_NUM_OF_CH; i++) {
		ch = &peripheral->channels[i];
		ch->fd = -1;
	}

	peripheral->name = strdup(name);
	list_add(&peripherals, &peripheral->node);

	return peripheral;
}

static void peripheral_destroy(struct peripheral* peripheral)
{
	int i;
	struct channel *ch;

	if (peripheral != NULL) {
		for (i = peripheral_ch_type_data; i < MAX_NUM_OF_CH; i++) {
			ch = &peripheral->channels[i];
			free(ch->name);
		}
		list_del(&peripheral->node);
		free(peripheral->name);
		free(peripheral);
	}
}

static int peripheral_set_channel(struct peripheral *peripheral,
								  const char *ch_name, enum peripheral_ch_type ch_type)
{
	if (peripheral != NULL) {
		diag_dbg(DIAG_DBG_PERIPHERAL, "Added to %s device channel %s\n", peripheral->name, ch_name);
		peripheral->channels[ch_type].name = strdup(ch_name);
		return 0;
	}

	return 1;
}

static int peripheral_udev_update(int fd, void *data)
{
	struct udev_monitor *mon = data;
	struct udev_device *dev;
	const char *devnode;
	const char *action;
	const char *rproc;
	const char *name;

	dev = udev_monitor_receive_device(mon);
	if (!dev)
		return 0;

	action = udev_device_get_action(dev);
	devnode = udev_device_get_devnode(dev);

	if (!devnode)
		goto unref_dev;

	if (strcmp(action, "add") == 0) {
		name = peripheral_udev_get_name(dev);
		rproc = peripheral_udev_get_remoteproc(dev);

		if (!name || !rproc)
			goto unref_dev;

		devnode_add(devnode, name, rproc);
		peripheral_open(peripheral_get_by_name(rproc));
	} else if (strcmp(action, "remove") == 0) {
		rproc = peripheral_udev_get_remoteproc(dev);

		if (!rproc)
			goto unref_dev;

		devnode_remove(devnode);
		peripheral_close(peripheral_get_by_name(rproc));
	} else {
		warn("unknown udev action");
	}

unref_dev:
	udev_device_unref(dev);

	return 0;
}

int peripheral_init()
{
	struct list_head *item;
	struct peripheral *peripheral;

	peripheral_udev_init();

	peripheral = peripheral_create("hexagon");
	peripheral_set_channel(peripheral, "DIAG", peripheral_ch_type_data);
	peripheral_set_channel(peripheral, "DIAG_CNTL", peripheral_ch_type_ctrl);
	peripheral_set_channel(peripheral, "DIAG_CMD", peripheral_ch_type_cmd);

	peripheral = peripheral_create("pronto");
	peripheral_set_channel(peripheral, "APPS_RIVA_DATA", peripheral_ch_type_data);
	peripheral_set_channel(peripheral, "APPS_RIVA_CTRL", peripheral_ch_type_ctrl);

	list_for_each(item, &peripherals) {
		peripheral = container_of(item, struct peripheral, node);
		peripheral_open(peripheral);
	}

	return 0;
}

int peripheral_exit()
{
	struct list_head *item;
	struct peripheral *peripheral;

	/* Destroy each device */
	list_for_each(item, &peripherals) {
		peripheral = container_of(item, struct peripheral, node);
		peripheral_destroy(peripheral);
	}

	return 0;
}
