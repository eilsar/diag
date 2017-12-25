DIAG := diag
SAMPLE := keep_alive.so

CFLAGS := -Wall -g -O2
LDFLAGS := -ldl -ludev

COMMON_SRCS := hdlc.c mbuf.c util.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)
SRCS := diag.c diag_cntl.c diag_router.c diag_transport.c diag_transport_sock.c diag_transport_uart.c diag_transport_usb.c masks.c peripheral.c watch.c
OBJS := $(SRCS:.c=.o)

$(DIAG): $(COMMON_OBJS) $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

SAMPLE_SRCS := ./keep_alive/keep_alive.c
SAMPLE_OBJS := $(SAMPLE_SRCS:.c=.o)

$(SAMPLE): $(COMMON_OBJS) $(SAMPLE_OBJS)
	$(CC) -shared -fPIC -o $@ $^ $(LDFLAGS)

install: $(DIAG) $(SAMPLE)
	install -D -m 755 $(DIAG) $(DESTDIR)$(prefix)/bin/$(DIAG)
	install -D -m 755 $(SAMPLE) $(DESTDIR)$(prefix)/lib/$(SAMPLE)

clean:
	rm -f $(COMMON_OBJS) $(DIAG) $(OBJS) $(SAMPLE) $(SAMPLE_OBJS)
