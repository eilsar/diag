DIAG := diag
FTM_BT := ftm_bt.so

CFLAGS := -Wall -g -O2
LDFLAGS := -ldl -ludev

COMMON_SRCS := hdlc.c mbuf.c util.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)
SRCS := diag.c diag_cntl.c diag_router.c diag_transport.c diag_transport_sock.c diag_transport_uart.c diag_transport_usb.c masks.c peripheral.c watch.c
OBJS := $(SRCS:.c=.o)

$(DIAG): $(COMMON_OBJS) $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

FTM_BT_SRCS := ./ftm_bt/ftm_bt.c
FTM_BT_OBJS := $(FTM_BT_SRCS:.c=.o)

$(FTM_BT): $(COMMON_OBJS) $(FTM_BT_OBJS)
	$(CC) -shared -fPIC -o $@ $^ $(LDFLAGS)

install: $(DIAG) $(SAMPLE) $(FTM_BT)
	install -D -m 755 $(DIAG) $(DESTDIR)$(prefix)/bin/$(DIAG)
	install -D -m 755 $(SAMPLE) $(DESTDIR)$(prefix)/lib/$(SAMPLE)
	install -D -m 755 $(FTM_BT) $(DESTDIR)$(prefix)/lib/$(FTM_BT)

clean:
	rm -f $(COMMON_OBJS) $(DIAG) $(OBJS) $(FTM_BT) $(FTM_BT_OBJS)
