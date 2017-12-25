/*
 * Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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
#ifndef __DIAG_DBG_H__
#define __DIAG_DBG_H__

#include <stdio.h>

extern unsigned int diag_dbg_mask;

enum diag_debug_mask {
	DIAG_DBG_NONE				= 0x00000000,
	DIAG_DBG_MAIN				= 0x00000001,
	DIAG_DBG_CNTL				= 0x00000002,
	DIAG_DBG_PERIPHERAL			= 0x00000004,
	DIAG_DBG_UTIL				= 0x00000008,
	DIAG_DBG_WATCH				= 0x00000010,
	DIAG_DBG_MAIN_DUMP			= 0x00010000,
	DIAG_DBG_CNTL_DUMP			= 0x00020000,
	DIAG_DBG_PERIPHERAL_DUMP	= 0x00040000,
	DIAG_DBG_UTIL_DUMP			= 0x00080000,
	DIAG_DBG_WATCH_DUMP			= 0x00100000,
	DIAG_DBG_ANY				= 0xffffffff,
};

#define pr_fmt(fmt) "DIAG: " fmt

#define diag_info(fmt, arg...) \
	printf(pr_fmt("INFO " fmt "\n"), ##arg)

#define diag_dbg(mask, fmt, arg...) do { \
	if (diag_dbg_mask & mask) \
		printf(pr_fmt("%s@%s#%u: " fmt), __FILE__, __FUNCTION__, __LINE__, ##arg); \
} while (0)

#define diag_dbg_dump(mask, prefix_str, buf, len) do { \
	if (diag_dbg_mask & mask) \
		print_hex_dump(pr_fmt(prefix_str), (buf), len); \
} while (0)

#endif // __DIAG_DBG_H__
