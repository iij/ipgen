include ../Makefile.inc

PROG=		ipgen
SRCS=		gen.c util.c webserv.c pbuf.c sequencecheck.c seqtable.c item.c genscript.c flowparse.c pktgen_item.c
CFLAGS+=	-I.. -I${LOCALBASE}/include -g -DHTDOCS=\"${PREFIX}/share/ipgen/htdocs\"
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+=	-Wreturn-type -Wswitch # -Wshadow XXX for gen.c
CFLAGS+=	-Wcast-qual -Wwrite-strings
CFLAGS+=	-Wextra
LDADD=		-L../libpkt -lpkt -L../libaddrlist -L${LOCALBASE}/lib -laddrlist -lpthread -lc -lcurses -levent -lmd

ifeq ($(shell uname),Linux)
LDADD+=		-lbsd -lcrypto -lbpf
CFLAGS+=	-DIPG_HACK -DUSE_AF_XDP
HAS_XDP_XSK_H:=	$(wildcard /usr/include/xdp/xsk.h)
ifdef HAS_XDP_XSK_H
CFLAGS+=	-DHAS_XDP_XSK_H
LDADD+=		-lxdp
endif
SRCS+=		arpresolv_linux.c af_xdp.c
else
CFLAGS+=	-DIPG_HACK -DUSE_NETMAP
CFLAGS+=	-DSUPPORT_PPPOE
SRCS+=		arpresolv.c
SRCS+=		pppoe.c
endif

OBJS+=  $(patsubst %.S,%.o,$(SRCS:%.c=%.o))

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDADD)

pktgen_item.c: pktgen.layout
	perl layout_generator pktgen.layout

depend: pktgen_item.c $(SRCS)
	$(MKDEP) $(CFLAGS) $(SRCS)

clean: clean_test
	rm -f pktgen_item.[ch]
	rm -f $(PROG) $(OBJS)

cleandir: clean
	rm -f .depend GPATH GRTAGS GSYMS GTAGS

install:
	install -o root -g wheel -m 550 ipgen ${DESTDIR}${PREFIX}/bin/
	install -o root -g wheel -m 755 -d ${DESTDIR}${MANDIR}/man1
	install -o root -g wheel -m 444 ipgen.1 ${DESTDIR}${MANDIR}/man1

sequencecheck: sequencecheck.c seqcheck_test.c
	$(CC) -o $@ sequencecheck.c $(CFLAGS) -DTEST

test_sequencecheck: sequencecheck
	./sequencecheck > sequencecheck.test.out
	diff -q sequencecheck.test.out sequencecheck.test.valid.out

test: test_sequencecheck

clean_test:
	rm -f sequencecheck sequencecheck.test.out

-include .depend
