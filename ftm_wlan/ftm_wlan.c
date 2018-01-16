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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/select.h>

#include "diag_dbg.h"
#include "diag_peripheral_plugin.h"
#include "ftm.h"
#include "hdlc.h"
#include "mbuf.h"
#include "util.h"

#include "libtcmd.h"
#include "wlan_nv.h"
#include "wlan_nv2.h"
#include "wlan_nv_parser.h"

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

/*=====================================================================
 Debugging utils
=====================================================================*/

unsigned int diag_dbg_mask = DIAG_DBG_NONE;

#define DPRINTF(fmt, arg...) diag_dbg(DIAG_DBG_PLUGIN, fmt, ##arg)

#define DUMP_CAP 2048

#define DDUMP(prefix, buf, len) diag_dbg_dump(DIAG_DBG_PLUGIN, prefix, (buf), (len) < DUMP_CAP ? (len) : DUMP_CAP)

/*=====================================================================
 WLAN Interface info
=====================================================================*/

bool ifs_init[32];

/*=====================================================================
 DIAG FTM subsystem command
=====================================================================*/

int diag_fd = -1;

int diag_handle_ftm_wlan(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len);

#define FTM_WLAN_CMD_CODE 22

static struct diag_cmd_registration_entry cmd_reg_entry = {
	.first_cmd = get_diag_cmd_subsys_ftm_key(FTM_WLAN_CMD_CODE),
	.last_cmd = get_diag_cmd_subsys_ftm_key(FTM_WLAN_CMD_CODE),
	.cb = &diag_handle_ftm_wlan
};

static struct diag_cmd_registration_table cmd_reg_table = {
	.hdr = { .num_of_entries = 1 },
	.table = &cmd_reg_entry
};

/*===========================================================================*/

int ftm_diag_encode_send(void *pkt, size_t length)
{
	size_t n, written = 0;
	uint8_t *outbuf;
	size_t outlen;

	DPRINTF("Encoding buffer of %lu bytes:\n", length);

	outbuf = hdlc_encode(pkt, length, &outlen);
	if (outbuf == NULL) {
		return -ENOMEM;
	}

	while (outlen > written) {
		n = write(diag_fd, outbuf + written, outlen - written);
		if (n < 0) {
			warn("Failed to write encoded %lu bytes to data channel\n", outlen);
			return n;
		}
		written += n;
	}

	return outlen;
}

/*=====================================================================
 FTM_WLAN commands
=====================================================================*/

#define FTM_WLAN_COMMON_OP 0

struct ftm_wlan_cmd_header {
	uint16_t cmd_id;            // command id (required) typically FTM_WLAN_COMMON_OP
	uint16_t cmd_data_len;      // request pkt data length, excluding the diag and ftm headers
	uint16_t cmd_rsp_pkt_size;  // rsp pkt size, 0 or size of response pkt if different than req pkt
} __packed;

/* All wcn36xx testmode interface commands specified in
 * WCN36XX_TM_ATTR_CMD
 */
enum wcn36xx_tm_cmd {
	/* Returns the supported wcn36xx testmode interface version in
	 * WCN36XX_TM_ATTR_VERSION. Always guaranteed to work. User space
	 * uses this to verify it's using the correct version of the
	 * testmode interface
	 */
	WCN36XX_TM_CMD_GET_VERSION = 0,

	/* The netdev interface must be down at the
	 * time.
	 */
	WCN36XX_TM_CMD_START = 1,

	/* Puts the driver back into OFF state.
	 */
	WCN36XX_TM_CMD_STOP = 2,

	/* The command used to transmit a PTT command to the firmware.
	 * Command payload is provided in WCN36XX_TM_ATTR_DATA.
	 */
	WCN36XX_TM_CMD_PTT = 3,
};

struct ftm_msg {
	uint16_t   msgId;
	uint16_t   msgBodyLength;
	uint32_t   respStatus;
	uint8_t    msgResponse[0];
};

#define QUALCOMM_MODULE_NUMBER 2

struct ftm_wlan_req_pkt_header {
	struct diagpkt_subsys_header diag_hdr;
	struct ftm_wlan_cmd_header   ftm_hdr;
	uint16_t                     module_type; // Typically QUALCOMM_MODULE_NUMBER
} __packed;

struct ftm_wlan_req_pkt {
	struct ftm_wlan_req_pkt_header ftm_wlan_hdr;
	uint16_t                       ftm_cmd_type; // enum wcn36xx_tm_cmd
	uint8_t                        data[0];      // struct ftm_msg
} __packed;

enum ftm_wlan_error_codes {
	FTM_ERR_CODE_PASS = 0,
	FTM_ERR_CODE_FAIL,
};

struct ftm_wlan_rsp_pkt {
	struct diagpkt_subsys_header diag_hdr;
	struct ftm_wlan_cmd_header   ftm_hdr;
	uint16_t                     result ; // enum ftm_wlan_error_codes
	uint8_t                      data[0]; // struct ftm_msg
} __packed;

static const struct diagpkt_subsys_header g_diag_hdr = {
	DIAG_CMD_SUBSYS_DISPATCH,
	DIAG_SUBSYS_FTM,
	FTM_WLAN_CMD_CODE
};

void *diagpkt_subsys_alloc(unsigned int length)
{
	struct ftm_wlan_rsp_pkt *pkt = NULL;

	if (-1 == diag_fd) {
		return pkt;
	}

	pkt = malloc(length);

	if (pkt != NULL) {
		memset(pkt, 0, length);
		pkt->diag_hdr = g_diag_hdr;
	}

	return pkt;
}

struct ftm_wlan_req_pkt *g_req = NULL;
struct ftm_wlan_rsp_pkt *g_rsp = NULL;

/*=====================================================================
 NV management
=====================================================================*/

struct nv_data {
	uint32_t	is_valid;
	uint32_t	magic_number;
	uint8_t	data[0];
} __packed;

static struct nv_state {
	struct nv_data *nv;
	size_t nvSize;
	enum nv_version_type nvVersion;
	uint8_t	  *dict;
	size_t dictSize;
	eNvTable   processingNVTable;
	uint32_t   targetNVTableSize;
	uint8_t   *targetNVTablePointer;
	uint32_t   processedNVTableSize;
	uint8_t   *tempNVTableBuffer;
} ftm_config;

#define NV_BIN_FILE "/lib/firmware/wlan/prima/WCNSS_qcom_wlan_nv.bin"
#define NV_DICT_FILE "/lib/firmware/wlan/prima/WCNSS_wlan_dictionary.dat"

static sHalNv g_nvContents;

/*============================
FUNCTION	read_nv_files

DESCRIPTION
  Read the NV files from persistence

DEPENDENCIES
  NIL

RETURN VALUE
  Returns 0 if files were successfully read otherwise error code

SIDE EFFECTS
  NONE
============================*/
static int read_nv_files()
{
	FILE *nvf;
	size_t size = 0;
	size_t count = 0;
	int ret = 0;
	sNvFields fields;

	ftm_config.nvSize = 0;
	ftm_config.nvVersion = E_NV_INVALID;
	ftm_config.dictSize = 0;

	ftm_config.processingNVTable = NV_MAX_TABLE;
	ftm_config.targetNVTableSize = 0;
	ftm_config.targetNVTablePointer = NULL;
	ftm_config.processedNVTableSize = 0;
	ftm_config.tempNVTableBuffer = malloc(MAX_NV_TABLE_SIZE);

	nvf = fopen(NV_BIN_FILE, "r");
	if (nvf == NULL) {
		warn("Failed to open bin file %s for reading\n", NV_BIN_FILE);
		ret = -1;
		goto err_out;
	}

	if (!fseek(nvf, 0, SEEK_END)) {
		size = ftell(nvf);
		diag_info("size=%lu\n", size);
		rewind(nvf);
	}

	ftm_config.nv = malloc(size);
	if (ftm_config.nv == NULL) {
		warn("Failed to allocate NV buffer %lu\n", size);
		ret = -1;
		goto err_out;
	}
	if ((count = fread(ftm_config.nv, 1, size, nvf)) == 0) {
		warn("Failed to read into NV buffer %lu\n", size);
		ret = -1;
		goto err_out;
	}
	ftm_config.nvSize = size - (sizeof(ftm_config.nv->is_valid) + sizeof(ftm_config.nv->magic_number));
	DPRINTF("nvSize=%lu\n", ftm_config.nvSize);
	fclose(nvf);

	if (MAGIC_NUMBER == ftm_config.nv->magic_number) {
		warn("Magic read as 0x%08X\n", ftm_config.nv->magic_number);
		ftm_config.nvVersion = E_NV_V3;
	} else {
		ftm_config.nvVersion = E_NV_V2;
	}

	// Parse content of bin file
	nvParser(ftm_config.nv->data, ftm_config.nvSize, &g_nvContents);

	fields = g_nvContents.fields;
	DPRINTF("\n\n\nREAD count=%lu!!!!!\n", count);
	DDUMP("productId=", &fields.productId, 1);
	DPRINTF("productBands=%02X\n", fields.productBands);
	DPRINTF("wlanNvRevId=%02X should be 2 WC3660\n", fields.wlanNvRevId); //0: WCN1312, 1: WCN1314, 2: WCN3660
	DPRINTF("numOfTxChains=%02X\n", fields.numOfTxChains);
	DPRINTF("numOfRxChains=%02X\n", fields.numOfRxChains);
	DDUMP("macAddr=", fields.macAddr, NV_FIELD_MAC_ADDR_SIZE);
	DDUMP("macAddr2=", fields.macAddr2, NV_FIELD_MAC_ADDR_SIZE);
	DDUMP("macAddr3=", fields.macAddr3, NV_FIELD_MAC_ADDR_SIZE);
	DDUMP("macAddr4=", fields.macAddr4, NV_FIELD_MAC_ADDR_SIZE);
	DDUMP("mfgSN=", fields.mfgSN, NV_FIELD_MFG_SN_SIZE);
	DPRINTF("couplerType=%02X\n", fields.couplerType);
	DPRINTF("nvVersion=%02X\n", fields.nvVersion);

	DDUMP("DATA:\n", ftm_config.nv, ftm_config.nvSize);

	if (ftm_config.nvVersion == E_NV_V3) {
		nvf = fopen(NV_DICT_FILE, "r");
		if (nvf == NULL) {
			warn("Failed to open bin file %s for reading\n", NV_DICT_FILE);
			ret = -1;
			goto err_out;
		}

		if (!fseek(nvf, 0, SEEK_END)) {
			size = ftell(nvf);
			diag_info("size=%lu\n", size);
			rewind(nvf);
		}

		ftm_config.dict = malloc(size);
		if (ftm_config.dict == NULL) {
			warn("Failed to allocate DICT buffer %lu\n", size);
			ret = -1;
			goto err_out;
		}
		if (!fread(ftm_config.dict, 1, size, nvf)) {
			warn("Failed to read into DICT buffer %lu\n", size);
			ret = -1;
			goto err_out;
		}
		ftm_config.dictSize = size;
		DPRINTF("dictSize=%lu\n", ftm_config.dictSize);
	}

err_out:
	if (nvf != NULL) {
		fclose(nvf);
	}

	return ret;
}

/*============================
FUNCTION	write_nv_files

DESCRIPTION
  Write the NV files back to persistence

DEPENDENCIES
  NIL

RETURN VALUE
  Returns 0 if files were successfully written otherwise error code

SIDE EFFECTS
  NONE
============================*/
static int write_nv_files()
{
	FILE *nvf = NULL;
	size_t size;
	char *backup;

	backup = tmpnam(NULL);

	nvf = fopen(backup, "w");
	if (nvf == NULL) {
		warn("Failed to open bin file %s for writing\n", backup);
		return -1;
	}

	size = ftm_config.nvSize + sizeof(ftm_config.nv->is_valid);
	if (!fwrite(ftm_config.nv, 1, size, nvf)) {
		warn("Failed to write NV buffer %lu\n", size);
		fclose(nvf);
		return -1;
	}

	fclose(nvf);
	if (rename(NV_BIN_FILE, backup)) {
		return -1;
	}

	return 0;
}

/*=====================================================================
 Command processing
=====================================================================*/

/*===========================================================================
FUNCTION   ftm_wlan_tcmd_rx

DESCRIPTION
   Call back handler

DEPENDENCIES
  NIL

RETURN VALUE
  NONE

SIDE EFFECTS
  NONE

===========================================================================*/

void ftm_wlan_tcmd_rx(void *buf, int len)
{
	struct ftm_msg *rsp_msg = buf;
	uint16_t tcmd = ((struct ftm_msg *)g_req->data)->msgId;
	uint16_t result = FTM_ERR_CODE_PASS;

	DPRINTF("Rx call back received with len %d\n", len);

	if (len > 0) {
		if (rsp_msg->msgId == tcmd) {
			DPRINTF("TCMD response for %04X matches request %04X!\n", tcmd, rsp_msg->msgId);
			result = rsp_msg->respStatus;
		} else {
			DPRINTF("TCMD response for %04X does NOT match request %04X!\n", tcmd, rsp_msg->msgId);
		}
	}

	g_rsp = diagpkt_subsys_alloc(sizeof(struct ftm_wlan_req_pkt) + len);

	if (g_rsp == NULL) {
		warn("Failed to allocate diag packet! tcmd: %d",
				tcmd);
		return;
	}

	g_rsp->ftm_hdr = g_req->ftm_wlan_hdr.ftm_hdr;
	g_rsp->ftm_hdr.cmd_rsp_pkt_size = sizeof(struct ftm_wlan_req_pkt) + len;
	g_rsp->result = result;

	if (buf && len != 0) {
		diag_info("Copying data to global response\n");
		memcpy(&g_rsp->data, buf, len);
	}
}

/*===========================================================================
FUNCTION   is_host_cmd

DESCRIPTION
  Filter ftm commands that do NOT need to be delegated to firmware

DEPENDENCIES
  NIL

RETURN VALUE
  Returns back whether command needs to be handled by host and not delegated to firmware

SIDE EFFECTS
  NONE

===========================================================================*/
static bool is_host_cmd(struct ftm_wlan_req_pkt *wlan_ftm_pkt)
{
	struct ftm_msg *msg;

	if (wlan_ftm_pkt->data == NULL) {
		goto err_out;
	}
	msg = (struct ftm_msg *)wlan_ftm_pkt->data;

	switch (msg->msgId) {
	case MSG_GET_NV_TABLE:
	case MSG_SET_NV_TABLE:
	case MSG_GET_NV_FIELD:
	case MSG_SET_NV_FIELD:
	case MSG_STORE_NV_TABLE:
	case MSG_GET_NV_BIN:
	case MSG_SET_NV_BIN:
	case MSG_GET_DICTIONARY:
		diag_info("Host command 0x%04X\n", msg->msgId);
		return true;
	default:
		break;
	}

err_out:
	return false;
}

/*===========================================================================
FUNCTION   process_host_cmd

DESCRIPTION
  Process ftm commands locally e.g. relating to NV

DEPENDENCIES
  NIL

RETURN VALUE
  Returns back buffer that is meant to be passed to the diag callback

SIDE EFFECTS
  NONE

===========================================================================*/
static struct ftm_wlan_rsp_pkt *process_host_cmd(struct ftm_wlan_req_pkt *wlan_ftm_pkt, size_t pkt_len) {
	struct ftm_wlan_rsp_pkt *rsp = NULL;
	struct ftm_msg *msg;
	uint32_t magicNumber = 0;

	if (wlan_ftm_pkt->data == NULL) {
		warn("No data!\n");
		goto err_out;
	}

	msg = (struct ftm_msg *)wlan_ftm_pkt->data;
	rsp = diagpkt_subsys_alloc(sizeof(struct ftm_wlan_req_pkt) + msg->msgBodyLength);

	if (rsp == NULL) {
		warn("Failed to allocate Diag packet\n");
		goto err_out;
	}

	rsp->ftm_hdr = wlan_ftm_pkt->ftm_wlan_hdr.ftm_hdr;
	rsp->ftm_hdr.cmd_rsp_pkt_size = sizeof(struct ftm_wlan_req_pkt) + msg->msgBodyLength;
	rsp->result = FTM_ERR_CODE_FAIL;
	memcpy(rsp->data, msg, pkt_len - sizeof(struct ftm_wlan_req_pkt));
	msg = (struct ftm_msg *)rsp->data;

	if (ftm_config.nv == NULL) {
		if (read_nv_files()) {
			goto err_out;
		}
	}

	switch (msg->msgId) {
#ifdef WLAN_NV2 // NV2 related commands
	case MSG_GET_NV_TABLE: {
		struct msg_get_nv_table *body = (struct msg_get_nv_table *)msg->msgResponse;
		sHalNvV2 *nvContents = (sHalNvV2 *) &g_nvContents;
		enum nv_version_type nvVersion = ftm_config.nvVersion;

		if (E_NV_V2 != nvVersion) {
			warn("%s : Not valid NV Version %d\n", "GET_NV_TABLE", nvVersion);
			return rsp;
		}
		DPRINTF("Returning NV table %d\n", body->nvTable);

		/* Test first chunk of NV table */
		if ((NV_MAX_TABLE == ftm_config.processingNVTable) ||
			(0 == ftm_config.processedNVTableSize)) {
			/* Set Current Processing NV table type */
			ftm_config.processingNVTable = body->nvTable;

			switch (body->nvTable) {
			case NV_TABLE_RATE_POWER_SETTINGS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.pwrOptimum);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.pwrOptimum;
				break;

			case NV_TABLE_REGULATORY_DOMAINS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.regDomains);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.regDomains;
				break;

			case NV_TABLE_DEFAULT_COUNTRY:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.defaultCountryTable);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.defaultCountryTable;
				break;

			case NV_TABLE_TPC_POWER_TABLE:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.plutCharacterized);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.plutCharacterized[0];
				break;

			case NV_TABLE_TPC_PDADC_OFFSETS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.plutPdadcOffset);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.plutPdadcOffset[0];
				break;

			case NV_TABLE_VIRTUAL_RATE:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.pwrOptimum_virtualRate);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.pwrOptimum_virtualRate[0];
				break;

			case NV_TABLE_RSSI_CHANNEL_OFFSETS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.rssiChanOffsets);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.rssiChanOffsets[0];
				break;

			case NV_TABLE_HW_CAL_VALUES:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.hwCalValues);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.hwCalValues;
				break;

			case NV_TABLE_FW_CONFIG:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.fwConfig);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.fwConfig;
				break;

			case NV_TABLE_ANTENNA_PATH_LOSS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.antennaPathLoss);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.antennaPathLoss[0];
				break;

			case NV_TABLE_PACKET_TYPE_POWER_LIMITS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.pktTypePwrLimits);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.pktTypePwrLimits[0][0];
				break;

			default:
				warn("Not Valid NV Table %d", body->nvTable);
				return rsp;
				break;
			}

			/* Set Current Processing NV table type */
			ftm_config.processingNVTable = body->nvTable;
			/* Copy target NV table value into temp context buffer */
			memcpy(ftm_config.tempNVTableBuffer,
				ftm_config.targetNVTablePointer,
				ftm_config.targetNVTableSize);
		}
		/* Copy next chunk of NV table value into response buffer */
		memcpy(&body->tableData,
				ftm_config.tempNVTableBuffer + ftm_config.processedNVTableSize,
				body->chunkSize);
		/* Update processed pointer to prepare next chunk copy */
		ftm_config.processedNVTableSize += body->chunkSize;

		if (ftm_config.targetNVTableSize == ftm_config.processedNVTableSize) {
			/* Finished to process last chunk of data, initialize buffer */
			ftm_config.processingNVTable = NV_MAX_TABLE;
			ftm_config.targetNVTableSize = 0;
			ftm_config.processedNVTableSize = 0;
			memset(ftm_config.tempNVTableBuffer, 0, MAX_NV_TABLE_SIZE);
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
	case MSG_SET_NV_TABLE: {
		struct msg_set_nv_table *body = (struct msg_set_nv_table *)msg->msgResponse;
		sHalNvV2 *nvContents = (sHalNvV2 *) &g_nvContents;
		DPRINTF("Setting NV table %d\n", body->nvTable);

		/* Test first chunk of NV table */
		if ((NV_MAX_TABLE == ftm_config.processingNVTable) ||
			(0 == ftm_config.processedNVTableSize)) {
			/* Set Current Processing NV table type */
			ftm_config.processingNVTable = body->nvTable;

			switch (body->nvTable) {
			case NV_TABLE_RATE_POWER_SETTINGS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.pwrOptimum);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.pwrOptimum;
				break;

			case NV_TABLE_REGULATORY_DOMAINS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.regDomains);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.regDomains;
				break;

			case NV_TABLE_DEFAULT_COUNTRY:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.defaultCountryTable);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.defaultCountryTable;
				break;

			case NV_TABLE_TPC_POWER_TABLE:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.plutCharacterized);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.plutCharacterized[0];
				break;

			case NV_TABLE_TPC_PDADC_OFFSETS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.plutPdadcOffset);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.plutPdadcOffset[0];
				break;

			case NV_TABLE_VIRTUAL_RATE:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.pwrOptimum_virtualRate);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.pwrOptimum_virtualRate[0];
				break;

			case NV_TABLE_RSSI_CHANNEL_OFFSETS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.rssiChanOffsets);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.rssiChanOffsets[0];
				break;

			case NV_TABLE_HW_CAL_VALUES:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.hwCalValues);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.hwCalValues;
				break;

			case NV_TABLE_FW_CONFIG:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.fwConfig);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.fwConfig;
				break;

			case NV_TABLE_ANTENNA_PATH_LOSS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.antennaPathLoss);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.antennaPathLoss[0];
				break;

			case NV_TABLE_PACKET_TYPE_POWER_LIMITS:
				ftm_config.targetNVTableSize = sizeof(nvContents->tables.pktTypePwrLimits);
				ftm_config.targetNVTablePointer = (uint8_t *)&nvContents->tables.pktTypePwrLimits[0][0];
				break;

			default:
				warn("Not Valid NV Table %d", body->nvTable);
				return rsp;
				break;
			}

			/* Set Current Processing NV table type */
			ftm_config.processingNVTable = body->nvTable;
		}

		/* Copy next chunk of NV table value from response buffer */
		memcpy(ftm_config.tempNVTableBuffer + ftm_config.processedNVTableSize,
			&body->tableData,
			body->chunkSize);
		/* Update processed pointer to prepare next chunk copy */
		ftm_config.processedNVTableSize += body->chunkSize;

		if (ftm_config.targetNVTableSize == ftm_config.processedNVTableSize) {
			memcpy(ftm_config.targetNVTablePointer,
				ftm_config.tempNVTableBuffer,
				ftm_config.targetNVTableSize);
			/* Finished to process last chunk of data, initialize buffer */
			ftm_config.processingNVTable = NV_MAX_TABLE;
			ftm_config.targetNVTableSize = 0;
			ftm_config.processedNVTableSize = 0;
			memset(ftm_config.tempNVTableBuffer, 0, MAX_NV_TABLE_SIZE);
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
#endif
#ifdef WLAN_NV3 // NV3 related commands
	case MSG_GET_NV_FIELD: {
		struct msg_get_nv_field *body = (struct msg_get_nv_field *) msg->msgResponse;
		sHalNv *nvContents = &g_nvContents;
		DPRINTF("Getting NV field %d\n",
			body->nvField);

		switch (body->nvField) {
		case NV_COMMON_PRODUCT_ID:
			memcpy((void *) &body->fieldData, &nvContents->fields.productId,
				sizeof(nvContents->fields.productId));
			break;

		case NV_COMMON_PRODUCT_BANDS:
			memcpy((void *) &body->fieldData, &nvContents->fields.productBands,
				sizeof(nvContents->fields.productBands));
			break;

		case NV_COMMON_NUM_OF_TX_CHAINS:
			memcpy((void *) &body->fieldData, &nvContents->fields.numOfTxChains,
				sizeof(nvContents->fields.numOfTxChains));
			break;

		case NV_COMMON_NUM_OF_RX_CHAINS:
			memcpy((void *) &body->fieldData, &nvContents->fields.numOfRxChains,
				sizeof(nvContents->fields.numOfRxChains));
			break;

		case NV_COMMON_MAC_ADDR:
			memcpy((void *) &body->fieldData, &nvContents->fields.macAddr[0],
				NV_FIELD_MAC_ADDR_SIZE);
			break;

		case NV_COMMON_MFG_SERIAL_NUMBER:
			memcpy((void *) &body->fieldData, &nvContents->fields.mfgSN[0],
				NV_FIELD_MFG_SN_SIZE);
			break;

		case NV_COMMON_WLAN_NV_REV_ID:
			memcpy((void *) &body->fieldData, &nvContents->fields.wlanNvRevId,
				sizeof(nvContents->fields.wlanNvRevId));
			break;

		case NV_COMMON_COUPLER_TYPE:
			memcpy((void *) &body->fieldData, &nvContents->fields.couplerType,
				sizeof(nvContents->fields.couplerType));
			break;

		case NV_COMMON_NV_VERSION: {
			uint8_t nvVersion = nvContents->fields.nvVersion;
			DPRINTF("nvVersion = %d\n", nvVersion);
			bool nvEmbedded = (ftm_config.nvVersion == E_NV_V3);

			if (nvEmbedded) {
				// High bit is set to indicate embedded NV..
				nvVersion = nvVersion | NV_EMBEDDED_VERSION;
			}

			DPRINTF("%sVersion=%d\n",
				nvEmbedded ? "embedded " : "", nvVersion);

			memcpy((void *) &body->fieldData, &nvVersion,
				sizeof(nvContents->fields.nvVersion));
			break;
		}

		default:
			warn("Not Valid NV field %d", body->nvField);
			return rsp;
			break;
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
	case MSG_SET_NV_FIELD: {
		struct msg_set_nv_field *body =	(struct msg_set_nv_field *) msg->msgResponse;
		sHalNv *nvContents = &g_nvContents;
		DPRINTF("Setting NV field %d\n",
			body->nvField);

		switch (body->nvField) {
		case NV_COMMON_PRODUCT_ID:
			memcpy(&nvContents->fields.productId, &body->fieldData,
				sizeof(nvContents->fields.productId));
			break;

		case NV_COMMON_PRODUCT_BANDS:
			memcpy(&nvContents->fields.productBands, &body->fieldData,
				sizeof(nvContents->fields.productBands));
			break;

		case NV_COMMON_NUM_OF_TX_CHAINS:
			memcpy(&nvContents->fields.numOfTxChains, &body->fieldData,
				sizeof(nvContents->fields.numOfTxChains));
			break;

		case NV_COMMON_NUM_OF_RX_CHAINS:
			memcpy(&nvContents->fields.numOfRxChains, &body->fieldData,
				sizeof(nvContents->fields.numOfRxChains));
			break;

		case NV_COMMON_MAC_ADDR: {
			uint8_t macLoop;
			uint8_t *pNVMac;
			uint8_t lastByteMAC;
			pNVMac = (uint8_t *) nvContents->fields.macAddr;
			lastByteMAC =
					body->fieldData.macAddr.macAddr1[NV_FIELD_MAC_ADDR_SIZE - 1];
			for (macLoop = 0; macLoop < 4; macLoop++) {
				memcpy(pNVMac + (macLoop * NV_FIELD_MAC_ADDR_SIZE),
					&body->fieldData.macAddr.macAddr1[0],
					NV_FIELD_MAC_ADDR_SIZE - 1);
				(pNVMac + (macLoop * NV_FIELD_MAC_ADDR_SIZE))
					[NV_FIELD_MAC_ADDR_SIZE - 1] = lastByteMAC + macLoop;
			}
			break;
		}

		case NV_COMMON_MFG_SERIAL_NUMBER:
			memcpy(&nvContents->fields.mfgSN[0], &body->fieldData,
				NV_FIELD_MFG_SN_SIZE);
			break;

		case NV_COMMON_WLAN_NV_REV_ID:
			memcpy(&nvContents->fields.wlanNvRevId, &body->fieldData,
				sizeof(nvContents->fields.wlanNvRevId));
			break;

		case NV_COMMON_COUPLER_TYPE:
			memcpy(&nvContents->fields.couplerType, &body->fieldData,
				sizeof(nvContents->fields.couplerType));
			break;

		case NV_COMMON_NV_VERSION:
			warn("Cannot modify NV version field %d", body->nvField);
			return rsp;
			break;

		default:
			warn("Not Valid NV field %d", body->nvField);
			return rsp;
			break;
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
	case MSG_STORE_NV_TABLE: {
		struct msg_store_nv_table* body =
			(struct msg_store_nv_table *) msg->msgResponse;
		DPRINTF("NOT Storing NV table %d\n", body->nvTable);
		if (write_nv_files()) {
			warn("Failed to persist NV file\n");
			return rsp;
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
	case MSG_GET_NV_BIN:
	case MSG_GET_DICTIONARY: {
		struct msg_get_nv_table *body =
			(struct msg_get_nv_table *) msg->msgResponse;
		size_t nvSize = 0;
		uint16_t offset = 0;
		enum nv_version_type nvVersion = ftm_config.nvVersion;

		if (E_NV_V3 != nvVersion) {
			warn("%s : Not valid NV Version %d", "GET_NV_BIN", nvVersion);
			return rsp;
		}
		DPRINTF("Returning NV table %d\n", body->nvTable);
		if ((NV_MAX_TABLE == ftm_config.processingNVTable)
			|| (0 == ftm_config.processedNVTableSize)) {
			switch (body->nvTable) {
			case NV_BINARY_IMAGE:
				if (msg->msgId == MSG_GET_NV_BIN) {
					ftm_config.targetNVTablePointer =
							(uint8_t *)&ftm_config.nv->magic_number;
					nvSize = ftm_config.nvSize;
				} else {
					ftm_config.targetNVTablePointer =
							ftm_config.dict;
					nvSize = ftm_config.dictSize;
				}
				break;
			default:
				warn("Not Valid NV Table %d", body->nvTable);
				return rsp;
				break;
			}

			/* Set Current Processing NV table type */
			ftm_config.processingNVTable = body->nvTable;
			if (msg->msgId == MSG_GET_NV_BIN) {
				ftm_config.targetNVTableSize = sizeof(uint32_t) + nvSize; // magic_number + data
				/* Validity Period */
				ftm_config.tempNVTableBuffer[0] = 0xFF;
				ftm_config.tempNVTableBuffer[1] = 0xFF;
				ftm_config.tempNVTableBuffer[2] = 0xFF;
				ftm_config.tempNVTableBuffer[3] = 0xFF;
				offset = sizeof(uint32_t); // skip is_valid
			} else {
				ftm_config.targetNVTableSize = nvSize;
				offset = 0;
			}

			DPRINTF("nvSize=%d, targetNVTableSize=%d, Offset=%d\n", nvSize,
				ftm_config.targetNVTableSize, offset);
			/* Copy target NV table value into temp context buffer */
			memcpy(&ftm_config.tempNVTableBuffer[offset],
				ftm_config.targetNVTablePointer,
				ftm_config.targetNVTableSize);
		}

		body->tableSize = ftm_config.targetNVTableSize;

		/* Update processed pointer to prepare next chunk copy */
		if ((body->chunkSize + ftm_config.processedNVTableSize) >
			ftm_config.targetNVTableSize) {
			body->chunkSize = (ftm_config.targetNVTableSize -
				ftm_config.processedNVTableSize);
		}

		DPRINTF("Copying to table data from offset=%d chunk=%d bytes\n",
			ftm_config.processedNVTableSize, body->chunkSize);
		/* Copy next chunk of NV table value into response buffer */
		memcpy(&body->tableData,
			ftm_config.tempNVTableBuffer + ftm_config.processedNVTableSize,
			body->chunkSize);

		ftm_config.processedNVTableSize += body->chunkSize;

		if (ftm_config.targetNVTableSize == ftm_config.processedNVTableSize) {
			/* Finished to process last chunk of data, initialize buffer */
			ftm_config.processingNVTable = NV_MAX_TABLE;
			ftm_config.targetNVTableSize = 0;
			ftm_config.processedNVTableSize = 0;
			memset(ftm_config.tempNVTableBuffer, 0, MAX_NV_TABLE_SIZE);
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
	case MSG_SET_NV_BIN: {
		struct msg_set_nv_table* body =
			(struct msg_set_nv_table *) msg->msgResponse;
		enum nv_version_type nvVersion = ftm_config.nvVersion;

		if (E_NV_V3 != nvVersion) {
			warn("%s : Not valid NV Version %d", "GET_NV_BIN", nvVersion);
			return rsp;
		}
		DPRINTF("Setting NV table %d\n",
			body->nvTable);
		ftm_config.targetNVTablePointer = (uint8_t *)ftm_config.nv;

		/* Test first chunk of NV table */
		if ((NV_MAX_TABLE == ftm_config.processingNVTable) ||
			(0 == ftm_config.processedNVTableSize)) {
			switch (body->nvTable) {
			case NV_BINARY_IMAGE:
				ftm_config.targetNVTableSize = body->tableSize;
				break;
			default:
				warn("Not Valid NV Table %d", body->nvTable);
				return rsp;
				break;
			}

			/* Set Current Processing NV table type */
			ftm_config.processingNVTable = body->nvTable;
			ftm_config.processedNVTableSize = 0;

			if (ftm_config.targetNVTableSize != body->tableSize) {
				warn("Invalid Table Size %d", body->tableSize);
				ftm_config.processingNVTable = NV_MAX_TABLE;
				ftm_config.targetNVTableSize = 0;
				ftm_config.processedNVTableSize = 0;
				memset(ftm_config.tempNVTableBuffer, 0, MAX_NV_TABLE_SIZE);
				return rsp;
			}
		}

		if (ftm_config.processingNVTable != body->nvTable) {
			warn("Invalid NV Table, now Processing %d, not %d",
				ftm_config.processingNVTable, body->nvTable);
			ftm_config.processingNVTable = NV_MAX_TABLE;
			ftm_config.targetNVTableSize = 0;
			ftm_config.processedNVTableSize = 0;
			memset(ftm_config.tempNVTableBuffer, 0, MAX_NV_TABLE_SIZE);
			return rsp;
		}

		memcpy(ftm_config.tempNVTableBuffer + ftm_config.processedNVTableSize,
			&body->tableData,
			body->chunkSize);

		ftm_config.processedNVTableSize += body->chunkSize;

		if (ftm_config.targetNVTableSize == ftm_config.processedNVTableSize) {
			DPRINTF("Processing Done!! write encoded Buffer %d",
				ftm_config.targetNVTableSize);

			memcpy(ftm_config.targetNVTablePointer, ftm_config.tempNVTableBuffer, ftm_config.targetNVTableSize);
			ftm_config.processingNVTable = NV_MAX_TABLE;
			ftm_config.targetNVTableSize = 0;
			ftm_config.processedNVTableSize = 0;
			memset(ftm_config.tempNVTableBuffer, 0, MAX_NV_TABLE_SIZE);
		}
		msg->respStatus = 0;
		rsp->result = FTM_ERR_CODE_PASS;

		break;
	}
#endif
	} // end of switch

err_out:
	return rsp;
}

/*===========================================================================
FUNCTION   ftm_wlan_common_op

DESCRIPTION
  Process ftm commands like load driver, Tx, Rx and few test commands

DEPENDENCIES
  NIL

RETURN VALUE
  Returns back buffer that is meant to be passed to the diag callback

SIDE EFFECTS
  NONE

===========================================================================*/
static struct ftm_wlan_rsp_pkt *ftm_wlan_common_op(struct ftm_wlan_req_pkt *wlan_ftm_pkt, size_t pkt_len)
{
	char ifname[IFNAMSIZ];
	int ifindex = 0;
	bool resp = false;
	struct ftm_wlan_rsp_pkt *rsp;
	size_t req_len = pkt_len - sizeof(struct ftm_wlan_req_pkt_header); // wlan_request_buffer length

	snprintf(ifname, sizeof(ifname), "wlan%d", ifindex);

	if (req_len <= 0) {
		warn("Invalid req_len: %d\n", req_len);
		return NULL;
	}

	DPRINTF("Command ID rec'd: 0x%02X + data length %d\n", wlan_ftm_pkt->ftm_cmd_type, req_len - sizeof(wlan_ftm_pkt->ftm_cmd_type));

	if (is_host_cmd(wlan_ftm_pkt)) { // Commands that are handled without delegation to firmware
		return process_host_cmd(wlan_ftm_pkt, pkt_len);
	} else { // Commands that are delegated to firmware via driver
		g_rsp = NULL;

		rsp = diagpkt_subsys_alloc(sizeof(struct ftm_wlan_rsp_pkt));

		if (rsp == NULL) {
			warn("Failed to allocate Diag packet\n");
			goto err_out;
		}

		rsp->ftm_hdr = wlan_ftm_pkt->ftm_wlan_hdr.ftm_hdr;
		rsp->result = FTM_ERR_CODE_PASS;

		// Force reinitialisation! TODO: Fix this hack
		ifs_init[ifindex] = false;
		if (!ifs_init[ifindex]) {
			DPRINTF("Initializing Interface: %s\n", ifname);

			if (tcmd_tx_init(ifname, ftm_wlan_tcmd_rx))
			{
				warn("Couldn't init tcmd transport!\n");
				rsp->result = FTM_ERR_CODE_FAIL;
				goto err_out;
			}

			DPRINTF("Initialized Interface: %s\n", ifname);
			ifs_init[ifindex] = true;
		} else {
			DPRINTF("Interface: %s already initialized\n", ifname);
		}

		resp = (wlan_ftm_pkt->ftm_cmd_type == WCN36XX_TM_CMD_PTT);
		g_req = wlan_ftm_pkt;
		if (tcmd_tx(wlan_ftm_pkt->ftm_cmd_type, (void *)wlan_ftm_pkt->data, req_len - sizeof(wlan_ftm_pkt->ftm_cmd_type), resp)) {
			warn("TCMD timed out!\n");
			rsp->result = FTM_ERR_CODE_FAIL;
			goto err_out;
		}

		if (resp) {
			if (g_rsp) {
				free(rsp);
				warn("Global response received from callback\n");
				return g_rsp;
			} else {
				warn("No response got probably timing out.... \n");
				rsp->result = FTM_ERR_CODE_FAIL;
				goto err_out;
			}
		}
	}

err_out:
	DPRINTF("Default response!\n");
	return rsp;
}

/*=====================================================================
 Diag Extension API
=====================================================================*/

int diag_handle_ftm_wlan(struct diag_cmd *dc, struct diag_client *client, void *buf, size_t len)
{
	size_t req_len = len, rsp_len;
	struct ftm_wlan_req_pkt *req_pkt = buf;
	struct ftm_wlan_rsp_pkt *rsp_pkt = NULL;
	int ret;

	if (req_pkt->ftm_wlan_hdr.module_type != QUALCOMM_MODULE_NUMBER) {
		warn("Invalid module_type: %d should be %d\n", req_pkt->ftm_wlan_hdr.module_type, QUALCOMM_MODULE_NUMBER);
		return 1;
	}

	switch (req_pkt->ftm_wlan_hdr.ftm_hdr.cmd_id) {
	case FTM_WLAN_COMMON_OP:
		rsp_pkt = ftm_wlan_common_op(req_pkt, req_len);
		if (rsp_pkt != NULL) {
			rsp_len = rsp_pkt->ftm_hdr.cmd_rsp_pkt_size;
			if (!rsp_len)
				rsp_len = sizeof(*req_pkt);
		}
		break;
	default:
		warn("Unknown Command\n");
		return 1;
	}
	if (rsp_pkt == NULL) {
		warn("No response!!!\n");
		return 1;
	}

	ret = ftm_diag_encode_send(rsp_pkt, rsp_len);
	if (ret < 0)
		return ret;

	return 0;
}

void diag_get_cmd_registration_table(struct diag_cmd_registration_table **tbl_ptr)
{
	*tbl_ptr = &cmd_reg_table;

	return;
}

int diag_set_pipe(int fd)
{
	diag_fd = fd;

	return 0;
}

int diag_set_debug_level(int level)
{
	diag_dbg_mask = level;

	return 0;
}
