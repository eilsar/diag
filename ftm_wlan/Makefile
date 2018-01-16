FTM_WLAN := ftm_wlan.so
LIBTCMD := libtcmd.a

CFLAGS := -Wall -g -O2 \
	-I.. \
	-I../ftm \
	-I./libtcmd \
	-I./wlan_nv \
	-DLIBNL_2 \
	-DWLAN_API_NL80211 \
	-DWLAN_NV3

LDFLAGS := -ldl -ludev -l:libnl-3.so -l:libnl-genl-3.so -lrt

COMMON_SRCS := hdlc.c mbuf.c util.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

LIBTCMD_SRCS := ./libtcmd/libtcmd.c ./libtcmd/nl80211.c ./libtcmd/os.c
LIBTCMD_OBJS := $(LIBTCMD_SRCS:.c=.o)

$(LIBTCMD): $(LIBTCMD_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	$(AR) rsc -o $@ $^

FTM_WLAN_SRCS := ftm_wlan.c ./wlan_nv/wlan_nv.c ./wlan_nv/wlan_nv_parser.c ./wlan_nv/wlan_nv_stream_read.c ./wlan_nv/wlan_nv_template_builtin.c
FTM_WLAN_OBJS := $(FTM_WLAN_SRCS:.c=.o)

$(FTM_WLAN): $(COMMON_OBJS) $(LIBTCMD_OBJS) $(FTM_WLAN_OBJS)
	$(CC) -shared -fPIC -o $@ $^ $(LDFLAGS)

install: $(FTM_WLAN)
	install -D -m 755 $(FTM_WLAN) $(DESTDIR)$(prefix)/lib/$(FTM_WLAN)

clean:
	rm -f $(COMMON_OBJS) $(FTM_WLAN) $(FTM_WLAN_OBJS) $(LIBTCMD_OBJS)
