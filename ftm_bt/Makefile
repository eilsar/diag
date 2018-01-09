FTM_BT := ftm_bt.so

CFLAGS := -Wall -g -O2 -I.. -I../ftm
LDFLAGS := -ldl -ludev

COMMON_SRCS := ../hdlc.c ../mbuf.c ../util.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

FTM_BT_SRCS := ftm_bt.c
FTM_BT_OBJS := $(FTM_BT_SRCS:.c=.o)

$(FTM_BT): $(COMMON_OBJS) $(FTM_BT_OBJS)
	$(CC) -shared -fPIC -o $@ $^ $(LDFLAGS)

install: $(FTM_BT)
	install -D -m 755 $(FTM_BT) $(DESTDIR)$(prefix)/lib/$(FTM_BT)

clean:
	rm -f $(COMMON_OBJS) $(FTM_BT) $(FTM_BT_OBJS)
