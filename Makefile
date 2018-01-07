DIAG := diag

CFLAGS := -Wall -g -O2
LDFLAGS := -ldl -ludev

SRCS := diag.c diag_cntl.c diag_router.c diag_transport.c diag_transport_sock.c diag_transport_uart.c diag_transport_usb.c hdlc.c masks.c mbuf.c peripheral.c util.c watch.c
OBJS := $(SRCS:.c=.o)

$(DIAG): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

install: $(DIAG)
	install -D -m 755 $< $(DESTDIR)$(prefix)/bin/$<

clean:
	rm -f $(DIAG) $(OBJS)
