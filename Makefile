DIAG := diag
FTM_WLAN := ftm_wlan.so
LIBTCMD := libtcmd.a

CFLAGS := -Wall -g -O2 \
	-I./ftm_wlan/libtcmd \
	-I./ftm_wlan/wlan_nv \
	-DLIBNL_2 \
	-DWLAN_API_NL80211 \
	-DWLAN_NV3

LDFLAGS := -ldl -ludev -l:libnl-3.so -l:libnl-genl-3.so -lrt

COMMON_SRCS := hdlc.c mbuf.c util.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)
SRCS := diag.c diag_cntl.c diag_router.c diag_transport.c diag_transport_sock.c diag_transport_uart.c diag_transport_usb.c masks.c peripheral.c watch.c
OBJS := $(SRCS:.c=.o)

$(DIAG): $(COMMON_OBJS) $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

LIBTCMD_SRCS := ./ftm_wlan/libtcmd/libtcmd.c ./ftm_wlan/libtcmd/nl80211.c ./ftm_wlan/libtcmd/os.c
LIBTCMD_OBJS := $(LIBTCMD_SRCS:.c=.o)

$(LIBTCMD): $(LIBTCMD_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	$(AR) rsc -o $@ $^

FTM_WLAN_SRCS := ./ftm_wlan/ftm_wlan.c ./ftm_wlan/wlan_nv/wlan_nv.c ./ftm_wlan/wlan_nv/wlan_nv_parser.c ./ftm_wlan/wlan_nv/wlan_nv_stream_read.c ./ftm_wlan/wlan_nv/wlan_nv_template_builtin.c
FTM_WLAN_OBJS := $(FTM_WLAN_SRCS:.c=.o)

$(FTM_WLAN): $(COMMON_OBJS) $(LIBTCMD_OBJS) $(FTM_WLAN_OBJS)
	$(CC) -shared -fPIC -o $@ $^ $(LDFLAGS)

install: $(DIAG) $(SAMPLE) $(FTM_BT) $(FTM_WLAN)
	install -D -m 755 $(DIAG) $(DESTDIR)$(prefix)/bin/$(DIAG)
	install -D -m 755 $(FTM_WLAN) $(DESTDIR)$(prefix)/lib/$(FTM_WLAN)

clean:
	rm -f $(COMMON_OBJS) $(DIAG) $(OBJS) $(FTM_WLAN) $(FTM_WLAN_OBJS) $(LIBTCMD_OBJS)
