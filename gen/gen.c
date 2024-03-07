/*
 * Copyright (c) 2016 Internet Initiative Japan, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <pthread.h>
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <err.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/random.h>
#include <net/if.h>
#ifdef USE_NETMAP
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include "netmap_user_localdebug.h"
#include <net/netmap_user.h>
#endif
#ifdef __linux__
#include <netinet/ether.h>
#include <linux/if.h>
#else
#include <machine/atomic.h>
#endif
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <event.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <bsd/string.h>
#endif

#include "compat.h"
#include "arpresolv.h"
#ifdef SUPPORT_PPPOE
#include "pppoe.h"
#endif
#include "libpkt/libpkt.h"
#include "libaddrlist/libaddrlist.h"
#include "util.h"
#include "webserv.h"
#include "gen.h"
#include "pbuf.h"
#include "sequencecheck.h"
#include "seqtable.h"
#include "item.h"
#include "genscript.h"
#include "flowparse.h"

#include "pktgen_item.h"

#ifdef USE_AF_XDP
#include "af_xdp.h"
#endif

#define	LINKSPEED_1GBPS		1000000000ULL
#define	LINKSPEED_10GBPS	10000000000ULL
#define	LINKSPEED_100GBPS	100000000000ULL

#define	DEFAULT_IFG		12	/* Inter Packet Gap */
#define	DEFAULT_PREAMBLE	(7 + 1)	/* preamble + SFD */
#define	FCS			4
#define	ETHHDRSIZE		sizeof(struct ether_header)

#define	PORT_DEFAULT		9	/* discard port */
#define MAXFLOWNUM		(1024 * 1024)

/* For old FreeBSD */
#if !defined(pthread_setname_np) && defined(pthread_set_name_np)
#define pthread_setname_np	pthread_set_name_np
#endif

#ifdef DEBUG
FILE *debugfh;
#endif

#define printf_verbose(fmt, args...)		\
	do {					\
		if (verbose > 0)		\
			printf(fmt, ## args);	\
	} while (0)


static void logging(char const *fmt, ...) __printflike(1, 2);
static void rfc2544_showresult(void);
static void rfc2544_showresult_json(char *);
static void quit(int);

char ipgen_version[] = "1.29";

#define DISPLAY_UPDATE_HZ	20
#define DEFAULT_PPS_HZ		1000
u_int pps_hz = DEFAULT_PPS_HZ;
u_int opt_npkt_sync = 0x7fffffff;
u_int opt_nflow = 0;

bool use_curses = true;

int use_ipv6 = 0;
int verbose = 0;
int opt_debuglevel = 0;
char *opt_debug = NULL;
int debug_tcpdump_fd;

int opt_fulldup = 0;
int opt_txonly = 0;
int opt_rxonly = 0;
int opt_gentest = 0;
int opt_addrrange = 0;
int opt_saddr = 0;
int opt_daddr = 0;
int opt_bps_include_preamble = 0;
int opt_allnet = 0;
int opt_fragment = 0;
int opt_tcp = 0;
int opt_udp = 1;	/* default */
int opt_ipg = 0;
int opt_time = 0;
int opt_fail_if_dropped = 0;
int opt_rfc2544 = 0;
double opt_rfc2544_tolerable_error_rate = 0.0;	/* default 0.00 % */
int opt_rfc2544_trial_duration = 60;	/* default 60sec */
char *opt_rfc2544_pktsize;
int opt_rfc2544_slowstart = 0;
double opt_rfc2544_ppsresolution = 0.0;	/* default 0.00% */
char *opt_rfc2544_output_json = NULL;
int opt_rfc2544_interval = 0;
int opt_rfc2544_warming_duration = 1;
int opt_rfc2544_early_finish = 1;

#ifdef IPG_HACK
int support_ipg = 0;
#endif


uint16_t opt_srcport_begin = PORT_DEFAULT;
uint16_t opt_srcport_end = PORT_DEFAULT;
uint16_t opt_dstport_begin = PORT_DEFAULT;
uint16_t opt_dstport_end = PORT_DEFAULT;

int opt_srcaddr_af;
int opt_dstaddr_af;
struct in_addr opt_srcaddr_begin;
struct in_addr opt_srcaddr_end;
struct in_addr opt_dstaddr_begin;
struct in_addr opt_dstaddr_end;
struct in6_addr opt_srcaddr6_begin;
struct in6_addr opt_srcaddr6_end;
struct in6_addr opt_dstaddr6_begin;
struct in6_addr opt_dstaddr6_end;

int opt_flowsort = 0;
int opt_flowdump = 0;
char *opt_flowlist = NULL;

u_int min_pktsize = 46;	/* not include ether-header. udp4:46, tcp4:46, udp6:54, tcp6:66 */

int force_redraw_screen = 0;
int do_quit = 0;

struct genscript *genscript;
int logfd = -1;

struct itemlist *itemlist;
char msgbuf[1024];

pthread_t txthread0;
pthread_t rxthread0;
pthread_t txthread1;
pthread_t rxthread1;
pthread_t controlthread;

const uint8_t eth_zero[6] = { 0, 0, 0, 0, 0, 0 };

char bps_desc[32];

#define CALC_L1 1
#define CALC_L2 0

#define	PKTSIZE2FRAMESIZE(x, gap)	(DEFAULT_PREAMBLE + (x) + FCS + (gap))
#define	_CALC_BPS(pktsize, pps, l1l2)											\
	(((pktsize) + ETHHDRSIZE + FCS + (((l1l2) == CALC_L1) ? DEFAULT_PREAMBLE + DEFAULT_IFG : 0)) * (pps) * 8.0)
#define	_CALC_MBPS(pktsize, pps, l1l2)			\
	(_CALC_BPS(pktsize, pps, l1l2) / 1000.0 / 1000.0)

static inline double
calc_bps(unsigned int pktsize, unsigned long pps)
{
	return _CALC_BPS(pktsize, pps, opt_bps_include_preamble ? CALC_L1 : CALC_L2);
}

#if 0 /* Not used yet */
static inline double
calc_bps_l1(unsigned int pktsize, unsigned long pps)
{
	return _CALC_BPS(pktsize, pps, CALC_L1);
}
#endif

static inline double
calc_mbps(unsigned int pktsize, unsigned long pps)
{
	return _CALC_MBPS(pktsize, pps, opt_bps_include_preamble ? CALC_L1 : CALC_L2);
}

static inline double
calc_mbps_l1(unsigned int pktsize, unsigned long pps)
{
	return _CALC_MBPS(pktsize, pps, CALC_L1);
}

/* sizeof(struct seqdata) = 6 bytes */
struct seqdata {
	uint32_t seq;
	uint16_t magic;
} __packed;
static uint16_t seq_magic;

struct interface {
	int opened;
#ifdef USE_NETMAP
	struct nm_desc *nm_desc;
#elif defined(USE_AF_XDP)
	struct ax_desc *ax_desc;
#endif
	char ifname[IFNAMSIZ];
	char drvname[IFNAMSIZ];
	unsigned long unit;	/* Unit number of the interface */
	char netmapname[128];
	char decorated_ifname[64];
	uint64_t maxlinkspeed;
	char twiddle[32];
	int promisc_save;

	struct interface_statistics {
		uint64_t tx_last;
		uint64_t rx_last;
		uint64_t tx_delta;
		uint64_t rx_delta;
		uint64_t tx_byte_last;
		uint64_t rx_byte_last;
		uint64_t tx_byte_delta;
		uint64_t rx_byte_delta;
		double tx_Mbps;
		double rx_Mbps;
		uint64_t tx_other;	/* arpreply, icmp-echoreply, etc */
		uint64_t tx;		/* include tx_other */
		uint64_t rx;		/* not include rx_* */
		uint64_t rx_flow;
		uint64_t rx_arp;
		uint64_t rx_icmp;
		uint64_t rx_icmpother;
		uint64_t rx_icmpecho;
		uint64_t rx_icmpunreach;
		uint64_t rx_icmpredirect;
		uint64_t rx_other;
		uint64_t rx_expire;
		uint64_t tx_underrun;
		uint64_t rx_seqrewind;

		uint64_t rx_seqdrop;
		uint64_t rx_seqdrop_last;
		uint64_t rx_seqdrop_delta;
		uint64_t rx_dup;
		uint64_t rx_dup_last;
		uint64_t rx_dup_delta;
		uint64_t rx_reorder;
		uint64_t rx_reorder_last;
		uint64_t rx_reorder_delta;
		uint64_t rx_outofrange;
		uint64_t rx_outofrange_last;
		uint64_t rx_outofrange_delta;


		uint64_t rx_seqdrop_flow;
		uint64_t rx_seqdrop_flow_last;
		uint64_t rx_seqdrop_flow_delta;
		uint64_t rx_dup_flow;
		uint64_t rx_dup_flow_last;
		uint64_t rx_dup_flow_delta;
		uint64_t rx_reorder_flow;
		uint64_t rx_reorder_flow_last;
		uint64_t rx_reorder_flow_delta;
		/*
		 * rx_outofrange is proveided only for per-interface
		 * because per-flow is not important.
		 */

		uint64_t tx_byte;
		uint64_t rx_byte;

		double latency_min;
		double latency_max;
		double latency_avg;
		double latency_sum;		/* for avg */
		uint64_t latency_npkt;		/* for avg */
	} stats;

	struct addresslist *adrlist;

	struct sequencechecker *seqchecker;	/* receive sequence drop checker */
	struct sequencechecker *seqchecker_flowtotal;
	struct sequencechecker **seqchecker_perflow;
	struct sequence_table *seqtable;	/* sequence info recorder */

	uint64_t sequence_tx;			/* transmit sequence number */
	uint64_t *sequence_tx_perflow;		/* transmit sequence number per flow*/

	unsigned int pktsize;	/* not include ether-header nor FCS */
	uint32_t transmit_pps;
	uint32_t transmit_pps_max;
	uint32_t transmit_txhz;
	double transmit_Mbps;
	int transmit_enable;
	int need_reset_statistics;

	struct pbufq pbufq;

	struct ether_addr eaddr;	/* my ethernet address */
	struct ether_addr gweaddr;	/* gw ethernet address */
	int pppoe;			/* PPPoE server mode. only IPv4 is supported. `ipaddr' and `gwaddr' must be specified */
#ifdef SUPPORT_PPPOE
	struct pppoe_softc pppoe_sc;
#endif
	int vlan_id;			/* vlan id. 0-4095. used only for TX */
	int af_addr;			/* AF_INET or AF_INET6 */
	struct in_addr ipaddr;		/* my IP address */
	struct in_addr ipaddr_mask;	/* my IP address mask */
	struct in6_addr ip6addr;	/* my IPv6 address */
	struct in6_addr ip6addr_mask;	/* my IPv6 address mask */
	int af_gwaddr;			/* AF_INET or AF_INET6 */
	struct in_addr gwaddr;		/* gw IP address */
	struct in6_addr gw6addr;	/* gw IPv6 address */
	int gw_l2random;		/* gw address is random (for L2 bridge test) */

} interface[2];

static char pktbuffer_ipv4[2][2][LIBPKT_PKTBUFSIZE] __attribute__((__aligned__(8)));
static char pktbuffer_ipv6[2][2][LIBPKT_PKTBUFSIZE] __attribute__((__aligned__(8)));
#define PKTBUF_UDP	0
#define PKTBUF_TCP	1

struct ifflag {
	const char drvname[IFNAMSIZ];
	uint64_t maxlinkspeed;
} ifflags[] = {
	{"em",  LINKSPEED_1GBPS},
	{"igb", LINKSPEED_1GBPS},
	{"bge", LINKSPEED_1GBPS},
	{"ix",  LINKSPEED_10GBPS},
	{"cc",	LINKSPEED_100GBPS},
	{"ice",	LINKSPEED_100GBPS},
	{"mce",	LINKSPEED_100GBPS},
};

struct timespec currenttime_tx;
struct timespec currenttime_main;
struct timespec starttime_tx;
sigset_t used_sigset;

static unsigned int build_template_packet_ipv4(int, char *);
static unsigned int build_template_packet_ipv6(int, char *);
static void touchup_tx_packet(char *, int);
static int packet_generator(char *, int);
#ifdef __linux__
static int getdrvname(const char *, char *);
#else
static int getifunit(const char *, char *, unsigned long *);
#endif
static void interface_wait_linkup(const char *);
static void interface_init(int);
static void interface_setup(int, const char *);
static void interface_open(int);
static void interface_close(int);
static int interface_need_transmit(int);
static int interface_load_transmit_packet(int, char *, uint16_t *);
static void icmpecho_handler(int, char *, int, int);
static void arp_handler(int, char *, int);
static void ndp_handler(int, char *, int);
#ifdef SUPPORT_PPPOE
static int pppoe_handler(int, char *);
#endif
static void receive_packet(int, struct timespec *, char *, uint16_t);
static void interface_receive(int);
static int interface_transmit(int);
static void *tx_thread_main(void *);
static void *rx_thread_main(void *);
static void genscript_play(void);
static void rfc2544_add_test(uint64_t, unsigned int);
static void rfc2544_load_default_test(uint64_t);
static void rfc2544_calc_param(uint64_t);
static void rfc2544_test(void);
static void control_init_items(struct itemlist *);
static void *control_thread_main(void *);
static void gentest_main(void);
static void generate_addrlists(void);


static unsigned int
build_template_packet_ipv4(int ifno, char *pkt)
{
	if (ifno == 0) {
		/* for interface0 -> interface1 */
		ethpkt_src(pkt, (u_char *)&interface[0].eaddr);
		ethpkt_dst(pkt, (u_char *)&interface[0].gweaddr);
		ip4pkt_src(pkt, sizeof(struct ether_header), interface[0].ipaddr.s_addr);
		ip4pkt_dst(pkt, sizeof(struct ether_header), interface[1].ipaddr.s_addr);
	} else {
		/* for interface1 -> interface0 */
		ethpkt_src(pkt, (u_char *)&interface[1].eaddr);
		ethpkt_dst(pkt, (u_char *)&interface[1].gweaddr);
		ip4pkt_src(pkt, sizeof(struct ether_header), interface[1].ipaddr.s_addr);
		ip4pkt_dst(pkt, sizeof(struct ether_header), interface[0].ipaddr.s_addr);
	}

	return interface[ifno].pktsize;
}

static unsigned int
build_template_packet_ipv6(int ifno, char *pkt)
{
	if (ifno == 0) {
		/* for interface0 -> interface1 */
		ethpkt_src(pkt, (u_char *)&interface[0].eaddr);
		ethpkt_dst(pkt, (u_char *)&interface[0].gweaddr);
		ip6pkt_src(pkt, sizeof(struct ether_header), &interface[0].ip6addr);
		ip6pkt_dst(pkt, sizeof(struct ether_header),  &interface[1].ip6addr);
	} else {
		/* for interface1 -> interface0 */
		ethpkt_src(pkt, (u_char *)&interface[1].eaddr);
		ethpkt_dst(pkt, (u_char *)&interface[1].gweaddr);
		ip6pkt_src(pkt, sizeof(struct ether_header), &interface[1].ip6addr);
		ip6pkt_dst(pkt, sizeof(struct ether_header), &interface[0].ip6addr);
	}

	return interface[ifno].pktsize;
}

inline static int
in_range(int num, int begin, int end)
{
	if (num < begin)
		return 0;
	if (num > end)
		return 0;
	return 1;
}

static inline u_int
get_flowid_max(int ifno)
{
	return addresslist_get_tuplenum(interface[ifno].adrlist) - 1;
}

static inline int
get_flownum(int ifno)
{
	return addresslist_get_tuplenum(interface[ifno].adrlist);
}

/* dstbuf must be 4 bytes larger than the size of srcbuf  */
static void
pktcpy_vlan(char *dstbuf, char *srcbuf, unsigned int pktsize, int vlan)
{
	/* copy src/dst mac */
	memcpy(dstbuf, srcbuf, 12);

	/* insert vlan tag */
	struct ether_vlan_header *evl = (struct ether_vlan_header *)dstbuf;
	evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
	evl->evl_tag = htons(vlan);

	/* copy original ethertype, and L2 payload */
	memcpy(dstbuf + 12 + 4, srcbuf + 12, pktsize - 12);
}

#ifdef SUPPORT_PPPOE
/* dstbuf must be 8 bytes larger than the size of srcbuf  */
static void
pktcpy_pppoe(char *dstbuf, char *srcbuf, unsigned int pktsize, uint16_t session, uint16_t type)
{
	/* copy src/dst mac */
	memcpy(dstbuf, srcbuf, ETHER_ADDR_LEN * 2);

	/* insert PPPoE header */
	struct pppoe_l2 *pppoe = (struct pppoe_l2 *)dstbuf;
	ethpkt_type(dstbuf, ETHERTYPE_PPPOE);
	pppoe->pppoe.vertype = PPPOE_VERTYPE;
	pppoepkt_code(dstbuf, 0);
	pppoepkt_session(dstbuf, session);
	pppoepkt_length(dstbuf, pktsize - ETHHDRSIZE + 2);
	pppoepkt_type(dstbuf, type);

	/* copy original ethertype, and L2 payload */
	memcpy(dstbuf + ETHER_HDR_LEN + 8, srcbuf + ETHER_HDR_LEN, pktsize - ETHER_HDR_LEN);
}
#endif

static void
touchup_tx_packet(char *buf, int ifno)
{
	struct interface *iface = &interface[ifno];
	struct interface *iface_other = &interface[ifno ^ 1];
	static unsigned int id;
	struct seqdata seqdata;
	uint32_t flowid;
	const struct address_tuple *tuple;
	int ipv6;
	unsigned int l3offset, l4payloadsize;
	struct sequence_record *seqrecord;

	if (iface->vlan_id) {
		l3offset = sizeof(struct ether_vlan_header);
#ifdef SUPPORT_PPPOE
	} else if (iface->pppoe) {
		l3offset = sizeof(struct pppoe_l2) + 2;
#endif
	} else {
		l3offset = sizeof(struct ether_header);
	}

	if (opt_gentest) {
		/* for benchmark (with -X option) */
		static uint32_t x = 0;

		ip4pkt_src(buf, l3offset, x);
		ip4pkt_dst(buf, l3offset, x);
		ip4pkt_srcport(buf, l3offset, x);
		ip4pkt_dstport(buf, l3offset, x);
		ip4pkt_length(buf, l3offset, iface->pktsize);

	} else {
		flowid = addresslist_get_current_tupleid(iface->adrlist);
		if (flowid >= opt_nflow) {
			addresslist_set_current_tupleid(iface->adrlist, 0);
			flowid = 0;
		}
		tuple = addresslist_get_current_tuple(iface->adrlist);
		addresslist_get_tuple_next(iface->adrlist);

		if (tuple->saddr.af == AF_INET) {
			int proto = opt_udp ? PKTBUF_UDP : PKTBUF_TCP;
			if (iface->vlan_id) {
				pktcpy_vlan(buf, pktbuffer_ipv4[proto][ifno], iface->pktsize + ETHHDRSIZE, iface->vlan_id);
#ifdef SUPPORT_PPPOE
			} else if (iface->pppoe) {
				pktcpy_pppoe(buf, pktbuffer_ipv4[proto][ifno], iface->pktsize + ETHHDRSIZE, iface->pppoe_sc.session, PPP_IP);
#endif
			} else {
				memcpy(buf, pktbuffer_ipv4[proto][ifno], iface->pktsize + ETHHDRSIZE);
			}

			ip4pkt_src(buf, l3offset, tuple->saddr.a.addr4.s_addr);
			ip4pkt_dst(buf, l3offset, tuple->daddr.a.addr4.s_addr);
			ip4pkt_srcport(buf, l3offset, tuple->sport);
			ip4pkt_dstport(buf, l3offset, tuple->dport);

			ip4pkt_length(buf, l3offset, iface->pktsize);
			ip4pkt_id(buf, l3offset, id++);
			if (opt_fragment)
				ip4pkt_off(buf, l3offset, 1200 | IP_MF);

			ipv6 = 0;
		} else {
			int proto = opt_udp ? PKTBUF_UDP : PKTBUF_TCP;
			if (iface->vlan_id) {
				pktcpy_vlan(buf, pktbuffer_ipv6[proto][ifno], iface->pktsize + ETHHDRSIZE, iface->vlan_id);
#ifdef SUPPORT_PPPOE
			} else if (iface->pppoe) {
				pktcpy_pppoe(buf, pktbuffer_ipv6[proto][ifno], iface->pktsize + ETHHDRSIZE, iface->pppoe_sc.session, PPP_IPV6);
#endif
			} else {
				memcpy(buf, pktbuffer_ipv6[proto][ifno], iface->pktsize + ETHHDRSIZE);
			}

			ip6pkt_src(buf, l3offset, &tuple->saddr.a.addr6);
			ip6pkt_dst(buf, l3offset, &tuple->daddr.a.addr6);
			ip6pkt_srcport(buf, l3offset, tuple->sport);
			ip6pkt_dstport(buf, l3offset, tuple->dport);

			ip6pkt_length(buf, l3offset, iface->pktsize);

			ipv6 = 1;
		}

		if (iface->gw_l2random)
			ethpkt_dst(buf, (const u_char *)tuple->deaddr.octet);
		if (iface_other->gw_l2random)
			ethpkt_src(buf, (const u_char *)tuple->seaddr.octet);

		if (ipv6)
			l4payloadsize = iface->pktsize - sizeof(struct ip6_hdr);
		else
			l4payloadsize = iface->pktsize - sizeof(struct ip);
		if (opt_udp)
			l4payloadsize -= sizeof(struct udphdr);
		else
			l4payloadsize -= sizeof(struct tcphdr);

		/* store sequence number, and remember relational info */
		seqrecord = seqtable_prep(iface_other->seqtable);
		seqdata.magic = seq_magic;
		seqdata.seq = seqrecord->seq;
		seqrecord->flowid = flowid;
		seqrecord->flowseq = iface->sequence_tx_perflow[flowid]++;
		seqrecord->ts = currenttime_tx;

		if (ipv6)
			ip6pkt_writedata(buf, l3offset, l4payloadsize - sizeof(seqdata), (char *)&seqdata, sizeof(seqdata));
		else
			ip4pkt_writedata(buf, l3offset, l4payloadsize - sizeof(seqdata), (char *)&seqdata, sizeof(seqdata));
	}
}

static int
packet_generator(char *buf, int ifno)
{
	struct interface *iface = &interface[ifno];
	int vlanadj;

	if (iface->vlan_id) {
		vlanadj = 4;
#ifdef SUPPORT_PPPOE
	} else if (iface->pppoe) {
		vlanadj = 8;
#endif
	} else {
		vlanadj = 0;
	}

	touchup_tx_packet(buf, ifno);

	if (opt_debug != NULL)
		tcpdumpfile_output(debug_tcpdump_fd, buf, iface->pktsize + ETHHDRSIZE + vlanadj);

	return iface->pktsize + vlanadj;
}

int
statistics_clear(void)
{
	interface[0].need_reset_statistics = 1;
	interface[1].need_reset_statistics = 1;

	return 0;
}

#ifdef __linux__
static int
getdrvname(const char *ifname, char *drvname)
{
	ssize_t n;
	char pathbuf[256];
	char linkbuf[256];
	char *drvstr;

	snprintf(pathbuf, sizeof(pathbuf), "/sys/class/net/%s/device/driver", ifname);
	n = readlink(pathbuf, linkbuf, sizeof(linkbuf));
	if (n == -1)
		return -1;

	/* ex /sys/bus/pci/drivers/ixgbe */
	drvstr = strrchr(linkbuf, '/');
	if (drvstr == NULL)
		return -1;
	drvstr++;
	strcpy(drvname, drvstr);

	return 0;
}
#else
static int
getifunit(const char *ifname, char *drvname, unsigned long *unit)
{
	u_int i;

	for (i = strlen(ifname) - 1; i > 0; i--)
		if (!isdigit(*(ifname + i)))
			break;
	if (((i == 0) && isdigit(ifname[0])) || /* All characters are digit */
	    (i == strlen(ifname) - 1)) /* The last character is not digit */
		return -1;

	i++;
	if (drvname != NULL) {
		strncpy(drvname, ifname, i);
		drvname[i] = 0;
	}
	*unit = strtoul(ifname + i, NULL, 10);

	return 0;
}
#endif

#ifdef IPG_HACK

#ifdef __linux__
static int
write_if_sysfs(const char *ifname, const char *target, unsigned int val)
{
	char path[64], buf[128];

	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, target);
	if (access(path, W_OK) != 0)
		return -1;
	snprintf(buf, sizeof(buf), "echo %u > %s", val, path);
	return system(buf);
}
#endif

/* set Transmit Inter Packet Gap */
static int
set_ipg(int ifno, unsigned int ipg)
{
	struct interface *iface = &interface[ifno];
#ifdef __linux__
	const char *ifname = iface->ifname;

	if (ifname == NULL || ifname[0] == '\0')
		return -1;
	DEBUGLOG("%s: setting tipg=%u\n", ifname, ipg);
	return write_if_sysfs(ifname, "tipg", ipg);
#else
	char buf[256];
	const char *drvname = iface->drvname;
	unsigned long unit = iface->unit;

	if ((strncmp(drvname, "em", IFNAMSIZ) == 0)
	    || (strncmp(drvname, "igb", IFNAMSIZ) == 0)
	    || (strncmp(drvname, "ix", IFNAMSIZ) == 0)) {
		snprintf(buf, sizeof(buf), "sysctl -q -w dev.%s.%lu.tipg=%d > /dev/null", drvname, unit, ipg);

		return system(buf);
	}
#endif

	return -1;
}

/* set Pause and Pace Register */
static int
set_pap(int ifno, unsigned int pap)
{
	struct interface *iface = &interface[ifno];
#ifdef __linux__
	const char *ifname = iface->ifname;

	if (ifname == NULL || ifname[0] == '\0')
		return -1;
	DEBUGLOG("%s: setting pap=%u\n", ifname, pap);
	return write_if_sysfs(ifname, "pap", pap);
#else
	char buf[256];
	const char *drvname = iface->drvname;
	unsigned long unit = iface->unit;

	if (strncmp(drvname, "ix", IFNAMSIZ) == 0) {
		snprintf(buf, sizeof(buf), "sysctl -q -w dev.%s.%ld.pap=%u > /dev/null", drvname, unit, pap);

		return system(buf);
	}

	return -1;
#endif
}
#endif /* IPG_HACK */

static void
reset_ipg(int ifno)
{
#ifdef IPG_HACK
	struct interface *iface = &interface[ifno];
	char buf[256];
	const char *drvname = iface->drvname;

#ifdef __linux__
#define BUILD_CMD(target, value)				\
	snprintf(buf, sizeof(buf),				\
	    "echo %d > /sys/class/net/%s/%s",			\
	    value, iface->ifname, target);
#else
#define BUILD_CMD(target, value)				\
	snprintf(buf, sizeof(buf),				\
	    "sysctl -q -w dev.%s.%lu.%s=%d > /dev/null",	\
	    drvname, iface->unit, target, value);
#endif

	if (!support_ipg)
		return;

	if ((strncmp(drvname, "em", IFNAMSIZ) == 0)
	    || (strncmp(drvname, "igb", IFNAMSIZ) == 0)) {
		BUILD_CMD("tipg", 8);
		system(buf);
	} else if (strncmp(drvname, "ix", IFNAMSIZ) == 0) {
		int rv;

		/* Try TIPG first */
		BUILD_CMD("tipg", 0);
		rv = system(buf);
		if (rv == 0)
			return;

		/* If failed, try PAP */
		BUILD_CMD("pap", 0);
		system(buf);
	}
#endif /* IPG_HACK */
}

/*
 * Check the availability of IPG and PAP features of the specified interface.
 * On success, the function will fulfill interface[ifno].drvname (on both FreeBSD and Linux)
 * and interface[ifno].unit (only on FreeBSD).
 */
static void
setup_ipg(const int ifno, const char *ifname)
{
#ifdef IPG_HACK
	char drvname[IFNAMSIZ];
#ifdef __linux__
	char path[256];

	if (getdrvname(ifname, drvname) == -1) {
		if (opt_ipg)
			printf("warning: failed to get drvname of %s\n", ifname);
		return;
	}

	snprintf(path, sizeof(path), "/sys/class/net/%s/tipg", ifname);
	if (access(path, R_OK|W_OK) == 0) {
		support_ipg = 1;
		if (opt_ipg)
			printf_verbose("%s TIPG feature supported\n", ifname);
	} else {
		snprintf(path, sizeof(path), "/sys/class/net/%s/pap", ifname);
		if (access(path, R_OK|W_OK) == 0) {
			support_ipg = 1;
			if (opt_ipg)
				printf_verbose("%s PAP feature supported\n", ifname);
		} else {
			if (opt_ipg) {
				printf("%s Neither TIPG feature nor PAP feature supported. Use %s driver patched for TIPG/PAP or drop the --ipg option.\n", drvname, drvname);
				exit(1);
			}
		}
	}
#else
	char strbuf[256];
	unsigned long unit;

	if (getifunit(ifname, drvname, &unit) == -1) {
		printf("warning: failed to get driver and unit of %s\n", ifname);
		return;
	}

	snprintf(strbuf, sizeof(strbuf), "sysctl -q dev.%s.%lu.tipg > /dev/null", drvname, unit);
	if (system(strbuf) == 0) {
		support_ipg = 1;
		if (opt_ipg)
			printf_verbose("%s%lu TIPG feature supported\n", drvname, unit);
	} else {
		snprintf(strbuf, sizeof(strbuf), "sysctl -q dev.%s.%lu.pap > /dev/null", drvname, unit);
		if (system(strbuf) == 0) {
			support_ipg = 1;
			if (opt_ipg)
				printf_verbose("%s%lu PAP feature supported\n", drvname, unit);
		} else {
			if (opt_ipg) {
				printf("%s%lu Neither TIPG feature nor PAP feature supported. Use %s driver patched for TIPG/PAP or drop the --ipg option.\n", drvname, unit, drvname);
				exit(1);
			}
		}
	}
	interface[ifno].unit = unit;
#endif
	strcpy(interface[ifno].drvname, drvname);
#endif /* IPG_HACK */
}

static void
update_transmit_max_sustained_pps(int ifno, int ipg)
{
	struct interface *iface = &interface[ifno];
	uint32_t maxpps;

	maxpps = iface->maxlinkspeed / 8 / PKTSIZE2FRAMESIZE(iface->pktsize + ETHHDRSIZE, ipg);

	if (iface->transmit_pps <= pps_hz)
		maxpps = iface->transmit_pps;

	iface->transmit_pps_max = maxpps;
}

static void
calc_ipg(int ifno)
{

	if (!opt_ipg) {
		update_transmit_max_sustained_pps(ifno, DEFAULT_IFG);
		return;
	}

#ifdef IPG_HACK
	struct interface *iface = &interface[ifno];
	int dev_tipg, ipg = DEFAULT_IFG;

	if (!support_ipg) {
		update_transmit_max_sustained_pps(ifno, DEFAULT_IFG);
		return;
	}

	if ((strncmp(iface->drvname, "em", 2) == 0) ||
	    (strncmp(iface->drvname, "igb", 3) == 0)) {

		if (iface->transmit_pps == 0) {
			dev_tipg = INT_MAX;
		} else {
			dev_tipg =
			    ((iface->maxlinkspeed / 8) / iface->transmit_pps) -
			    PKTSIZE2FRAMESIZE(iface->pktsize + ETHHDRSIZE, 0);
		}
		dev_tipg -= 4;	/* igb(4) NIC, ipg has offset 4 */
		if (dev_tipg < 8)
			dev_tipg = 8;
		if (dev_tipg >= 1024)
			dev_tipg = 1023;
		set_ipg(ifno, dev_tipg);

		ipg = dev_tipg + 4;	/* restore offset */
		update_transmit_max_sustained_pps(ifno, ipg);
	} else if (strncmp(iface->drvname, "ix", 2) == 0) {
		unsigned long bps;
		uint32_t new_pap;
		int error;

		if (iface->transmit_pps == 0) {
			dev_tipg = INT_MAX;
		} else {
			dev_tipg =
			    ((iface->maxlinkspeed / 8) / iface->transmit_pps) -
			    PKTSIZE2FRAMESIZE(iface->pktsize + ETHHDRSIZE, 0);
		}
		if (dev_tipg < 5)
			dev_tipg = 5;

		dev_tipg -= 4;	/* ix(4) NIC, ipg has offset 4 */
		if (dev_tipg >= 256)
			dev_tipg = 255;

		error = set_ipg(ifno, dev_tipg);
		if (error == 0) {
			ipg = dev_tipg + 4;	/* restore offset */
			update_transmit_max_sustained_pps(ifno, ipg);
			return;
		}

		/* 82599 and newer */
		if (iface->transmit_pps == 0) {
			bps = 0;
		} else {
			bps = PKTSIZE2FRAMESIZE(iface->pktsize + ETHHDRSIZE, DEFAULT_IFG) * iface->transmit_pps * 8;
		}
		/*  / 1000 / 1000; */

		DEBUGLOG("pps=%u, bps=%lu\n", iface->transmit_pps, bps);
		/* Need some margin to avoid underestimate. */
		bps = (unsigned long)((double)bps * 1.02);
		DEBUGLOG("pps=%u, bps=%lu\n", iface->transmit_pps, bps);
		if ((bps % (iface->maxlinkspeed / 10)) > 0)
			bps += iface->maxlinkspeed / 10;
		new_pap = bps / (iface->maxlinkspeed / 10);

		if (new_pap == 0)
			new_pap = 1;
		if (new_pap >= 10)
			new_pap = 0;

		error = set_pap(ifno, new_pap);
		if (error == 0) {
			ipg = dev_tipg + 4;	/* restore offset */
			update_transmit_max_sustained_pps(ifno, ipg);
			return;
		}
	}
#endif /* IPG_HACK */
}

static void
ipg_enable(int enable)
{
#ifdef IPG_HACK
	if (!support_ipg)
		enable = 0;
#endif
	if (itemlist != NULL) {
		if (enable) {
			itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_STEADY, "*");
			itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BURST, NULL);
		} else {
			itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_STEADY, NULL);
			itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BURST, "*");
		}
	}

	if (enable) {
		if (itemlist != NULL)
			itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BURST, NULL);
		opt_ipg = 1;
		calc_ipg(0);
		calc_ipg(1);

	} else {
		reset_ipg(0);
		reset_ipg(1);
		update_transmit_max_sustained_pps(0, DEFAULT_IFG);
		update_transmit_max_sustained_pps(1, DEFAULT_IFG);

		opt_ipg = 0;
	}
}

static void
update_min_pktsize(void)
{
	if (use_ipv6) {
		if (opt_tcp)
			min_pktsize = MAX(min_pktsize, sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + sizeof(struct seqdata));
		else
			min_pktsize = MAX(min_pktsize, sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct seqdata));
	} else {
		if (opt_tcp)
			min_pktsize = MAX(min_pktsize, sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct seqdata));
		else
			min_pktsize = MAX(min_pktsize, sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct seqdata));
	}
}

static void
update_transmit_Mbps(int ifno)
{
	struct interface *iface = &interface[ifno];

	if (iface->pktsize < min_pktsize)
		iface->pktsize = min_pktsize;
	if (iface->pktsize > 1500)
		iface->pktsize = 1500;

	if (iface->transmit_enable) {
		iface->transmit_Mbps = calc_mbps(iface->pktsize, iface->transmit_pps);
	} else {
		iface->transmit_Mbps = 0.0;
	}
	calc_ipg(ifno);
}

int
setpktsize(int ifno, unsigned int size)
{
	if (size < min_pktsize || size > 1500)
		return -1;

	interface[ifno].pktsize = size;
	update_transmit_Mbps(ifno);

	return 0;
}

unsigned int
getpktsize(int ifno)
{
	return interface[ifno].pktsize;
}

int
setpps(int ifno, unsigned long pps)
{
	interface[ifno].transmit_pps = pps;
	update_transmit_Mbps(ifno);

	return 0;
}

const char *
getifname(int ifno)
{
	return interface[ifno].ifname;
}

unsigned long
getpps(int ifno)
{
	return interface[ifno].transmit_pps;
}

void
transmit_set(int ifno, int on)
{
	if (itemlist != NULL) {
		switch (ifno) {
		case 0:
			if (on) {
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF0_START, "*");
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF0_STOP, NULL);
			} else {
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF0_START, NULL);
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF0_STOP, "*");
			}
			break;
		case 1:
			if (on) {
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF1_START, "*");
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF1_STOP, NULL);
			} else {
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF1_START, NULL);
				itemlist_setvalue(itemlist, ITEMLIST_ID_IF1_STOP, "*");
			}
			break;
		}
	}

	interface[ifno].transmit_enable = on;
	update_transmit_Mbps(ifno);
}

static void
interface_wait_linkup(const char *ifname)
{
	int i;

	printf_verbose("%s: waiting link up .", ifname);
	fflush(stdout);
	for (i = 100; i >= 0; i--) {
		if (interface_is_active(ifname))
			break;
		usleep(500000);
		printf_verbose(".");
		fflush(stdout);
	}
	if (i >= 0) {
		printf_verbose(" OK\n");
	} else {
		printf_verbose(" giving up\n");
	}
	fflush(stdout);
}

static void
interface_init(int ifno)
{
	interface[ifno].seqtable = seqtable_new();
	interface[ifno].seqchecker = seqcheck_new();
}

static void
interface_setup(int ifno, const char *ifname)
{
	struct interface *iface = &interface[ifno];

	strcpy(iface->ifname, ifname);
	sprintf(iface->decorated_ifname, "Interface: %s", ifname);
	getiflinkaddr(ifname, &iface->eaddr);

	if ((iface->ipaddr.s_addr == 0) && ipv6_iszero(&iface->ip6addr)) {
		getifipaddr(ifname, &iface->ipaddr, &iface->ipaddr_mask);
		getifip6addr(ifname, &iface->ip6addr, &iface->ip6addr_mask);
	}

	if (iface->gw_l2random) {
		fprintf(stderr, "L2 destination address is random\n");

#ifdef SUPPORT_PPPOE
	} else if (iface->pppoe) {
		int rc;
		struct pppoe_softc *sc = &iface->pppoe_sc;

		memset(sc, 0, sizeof(struct pppoe_softc));
		sc->ifname = iface->ifname;
		sc->srcip = iface->ipaddr;
		sc->dstip = iface->gwaddr;
		sc->session = getpid() & 0xffff;
		getrandom(&sc->magic, sizeof(sc->magic), 0);

		fprintf(stderr, "%s: accepting PPPoE...\n", iface->ifname);

		rc = pppoe_server(iface->ifname, sc);
		if (rc != 1) {
			fprintf(stderr, "%s: PPPoE connection could not be established\n", iface->ifname);
			exit(1);
		}

		memcpy(&iface->gweaddr, &sc->dstmac, ETHER_ADDR_LEN);

		fprintf(stderr, "%s: PPPoE established\n", iface->ifname);

#endif
	} else if (memcmp(eth_zero, &iface->gweaddr, ETHER_ADDR_LEN) == 0) {
		/* need to resolv arp */
		struct ether_addr *mac;
		char *addrstr = NULL;

		interface_wait_linkup(iface->ifname);

		switch (iface->af_gwaddr) {
		case AF_INET:
			mac = arpresolv(ifname, iface->vlan_id, &iface->ipaddr, &iface->gwaddr);
			addrstr = ip4_sprintf(&iface->gwaddr);
			break;
		case AF_INET6:
			mac = ndpresolv(ifname, iface->vlan_id, &iface->ip6addr, &iface->gw6addr);
			addrstr = ip6_sprintf(&iface->gw6addr);
			break;
		default:
			fprintf(stderr, "unknown address family to resolve mac-address of gateway\n");
			exit(1);
		}

		if (mac == NULL) {
			fprintf(stderr, "cannot resolve arp/ndp. mac-address of gateway:%s on %s is unknown\n",
			    addrstr, ifname);
			exit(1);
		}

		memcpy(&iface->gweaddr, mac, ETHER_ADDR_LEN);

		printf_verbose("arp/ndp resolved. %s on %s = %s\n",
		    addrstr,
		    iface->ifname,
		    ether_ntoa(&iface->gweaddr));
	}
}

static void
interface_open(int ifno)
{
	struct interface *iface = &interface[ifno];
	struct interface *iface_other = &interface[ifno ^ 1];
#ifdef USE_NETMAP
	struct nmreq nmreq;
	struct netmap_if *nifp;
	struct netmap_ring *txring, *rxring;

	memset(&nmreq, 0, sizeof(nmreq));
	sprintf(iface->netmapname, "netmap:%s", iface->ifname);

	iface->nm_desc = nm_open(iface->netmapname, &nmreq, 0, NULL);
	if (iface->nm_desc == NULL) {
		fprintf(stderr, "cannot open /dev/netmap\n");
		exit(1);
	}


	nifp = iface->nm_desc->nifp;
	txring = NETMAP_TXRING(nifp, 0);
	rxring = NETMAP_RXRING(nifp, 0);

	printf("%s: %d TX rings * %u slots, %d RX rings * %u slots", iface->ifname,
	    iface->nm_desc->last_tx_ring - iface->nm_desc->first_tx_ring + 1,
	    txring->num_slots,
	    iface->nm_desc->last_rx_ring - iface->nm_desc->first_rx_ring + 1,
	    rxring->num_slots
	);

	if (iface->nm_desc->done_mmap)
		printf(", %u MB mapped", iface->nm_desc->memsize / 1024 / 1024);
	printf("\n");

#elif defined(USE_AF_XDP)
	iface->ax_desc = ax_open(iface->ifname);
	if (iface->ax_desc == NULL) {
		fprintf(stderr, "failed to initialize AF_XDP\n");
		exit(1);
	}
#endif

	/* for IPv6 multicast packet (ndp, etc), or bridge random L2 address mode */
	if (use_ipv6 || iface_other->gw_l2random)
		interface_promisc(iface->ifname, true, &iface->promisc_save);

	iface->opened = 1;
}

/*
 * This function should be called after finishing TX/TX threads.
 */
void
interface_close(int ifno)
{
	struct interface *iface = &interface[ifno];
	struct interface *iface_other = &interface[ifno ^ 1];

	if (use_ipv6 || iface_other->gw_l2random)
		interface_promisc(iface->ifname, iface->promisc_save, NULL);

#ifdef USE_NETMAP
	nm_close(iface->nm_desc);
#elif defined(USE_AF_XDP)
	/*
	 * timeout of poll() in rx_thread_main() is 100ms,
	 * sleeping 200ms to wait returning from poll().
	 */
	usleep(200000);
	ax_close(iface->ax_desc);
#endif
	reset_ipg(ifno);

	iface->opened = 0;

	if (iface->af_gwaddr != 0) {
		memset(&iface->gweaddr, 0, ETHER_ADDR_LEN);
	}
}

static int
interface_need_transmit(int ifno)
{
	int n;

	n = pbufq_nqueued(&interface[ifno].pbufq);

	if (interface[ifno].transmit_enable)
		n += atomic_fetchadd_32(&interface[ifno].transmit_txhz, 0);

	return n;
}

static int
interface_load_transmit_packet(int ifno, char *buf, uint16_t *lenp)
{
	struct interface *iface = &interface[ifno];

	if (pbufq_poll(&iface->pbufq) != NULL) {
		struct pbuf *p;
		p = pbufq_dequeue(&iface->pbufq);
		memcpy(buf, p->data, p->len);
		*lenp = p->len;
		pbuf_free(p);

		iface->stats.tx_other++;

		return 2;	/* control packet */

	} else if (iface->transmit_enable) {

		for (;;) {
			uint32_t x = atomic_fetchadd_32(&iface->transmit_txhz, 0);
			if (x) {
				if (atomic_cmpset_32(&iface->transmit_txhz, x, x - 1))
					break;
			} else {
				return -1;
			}
		}

		int len;
		len = packet_generator(buf, ifno);
		*lenp = len + ETHHDRSIZE;

		return 1;	/* pktgen packet */

	}
	return -1;
}

static void
icmpecho_handler(int ifno, char *pkt, int len, int l3offset)
{
	struct interface *iface = &interface[ifno];
	struct pbuf *p;
	int pktlen;

	p = pbuf_alloc(len);
	if (p == NULL) {
		fprintf(stderr, "cannot allocate buffer for icmp request\n");
	} else {
		pktlen = ip4pkt_icmp_echoreply(p->data, l3offset, pkt, len);
		if (pktlen > 0) {
			ethpkt_src(p->data, (u_char *)&iface->eaddr);
			ethpkt_dst(p->data, (u_char *)&iface->gweaddr);
			p->len = pktlen;
			pbufq_enqueue(&iface->pbufq, p);
		} else {
			pbuf_free(p);
		}
	}
}

static void
arp_handler(int ifno, char *pkt, int l3offset)
{
	struct interface *iface = &interface[ifno];
	int pktlen;
	struct ether_addr eaddr;
	struct in_addr spa, tpa;
	int op;

	ip4pkt_arpparse(pkt + l3offset, &op, &eaddr, &spa.s_addr, &tpa.s_addr);
	if (op == ARPOP_REPLY) {
		/* ignore arp reply */
		return;
	}

	/* must to reply arp-query */
	if (op == ARPOP_REQUEST) {
		struct pbuf *p;

		switch (iface->af_gwaddr) {
		case AF_INET:
			/* don't answer gateway address */
			if (tpa.s_addr == iface->gwaddr.s_addr)
				return;
			break;

		case AF_INET6:
		default:
			break;
		}

		p = pbuf_alloc(ETHER_MAX_LEN);
		if (p == NULL) {
			fprintf(stderr, "cannot allocate buffer for arp request\n");
		} else {
			pktlen = ip4pkt_arpreply(p->data, pkt,
			    iface->eaddr.octet,
			    iface->ipaddr.s_addr,
			    iface->ipaddr_mask.s_addr);

			if (pktlen > 0) {
				p->len = pktlen;
				pbufq_enqueue(&iface->pbufq, p);
			} else {
				pbuf_free(p);
			}
		}
	}
}

void
ndp_handler(int ifno, char *pkt, int l3offset)
{
	struct interface *iface = &interface[ifno];
	int pktlen;
	struct in6_addr src, target;
	int type;

	ip6pkt_neighbor_parse(pkt + l3offset, &type, &src, &target);

	/* must to reply neighbor-advertize */
	if (type == ND_NEIGHBOR_SOLICIT) {
		struct pbuf *p;

		switch (iface->af_gwaddr) {
		case AF_INET6:
			/* don't answer gateway address */
			if (IN6_ARE_ADDR_EQUAL(&target, &iface->gw6addr))
				return;
			break;

		case AF_INET:
		default:
			break;
		}

		p = pbuf_alloc(ETHER_MAX_LEN);
		if (p == NULL) {
			fprintf(stderr, "cannot allocate buffer for arp request\n");
		} else {
			pktlen = ip6pkt_neighbor_solicit_reply(p->data, pkt,
			    iface->eaddr.octet,
			    &iface->ip6addr);

			if (pktlen > 0) {
				p->len = pktlen;
				pbufq_enqueue(&iface->pbufq, p);
			} else {
				pbuf_free(p);
			}
		}
	}
}

#ifdef SUPPORT_PPPOE
static int
pppoe_handler(int ifno, char *pkt)
{
	struct pppoe_l2 *req;
	struct pppoeppp *pppreq;
	struct pppoe_softc *sc;
	struct pbuf *p;
	int pktlen, rc = 0;
	unsigned char pppopt[128];

	sc = &interface[ifno].pppoe_sc;

	req = (struct pppoe_l2 *)pkt;
	pppreq = (struct pppoeppp *)(req + 1);

	if (ntohs(pppreq->protocol) == PPP_LCP) {
		switch (pppreq->ppp.type) {
		case ECHO_REQ:
			p = pbuf_alloc(ETHER_MAX_LEN);
			if (p == NULL) {
				fprintf(stderr, "cannot allocate buffer for arp request\n");
			} else {
				char *pktbuf = p->data;
				pktlen = ntohs(req->pppoe.plen) + sizeof(struct pppoe_l2);

				memset(pktbuf, 0, pktlen);
				pppoepkt_template(pktbuf, ETHERTYPE_PPPOE);
				ethpkt_dst(pktbuf, req->eheader.ether_shost);
				pppoepkt_session(pktbuf, sc->session);
				pktlen = pppoepkt_ppp_set(pktbuf, PPP_LCP, ECHO_REPLY, pppreq->ppp.id);

				/* add a magic */
				memcpy(pppopt, &sc->magic, 4);
				pktlen = pppoepkt_ppp_add_data(pktbuf, pppopt, 4);
				if (pktlen > 0) {
					p->len = pktlen;
					pbufq_enqueue(&interface[ifno].pbufq, p);
				} else {
					pbuf_free(p);
				}

			}
			rc = 1;
			break;
		case TERM_REQ:
			/* XXX */
			logging("%s: LCP TERM-REQ received", interface[ifno].ifname);
			break;
		}
	}

	return rc;
}
#endif

static void
receive_packet(int ifno, struct timespec *curtime, char *buf, uint16_t len)
{
	struct interface *iface = &interface[ifno];
	struct interface_statistics *ifstats = &iface->stats;
	int is_ipv6 = 0;
	struct ether_header *eth;
	struct ip *ip;
	struct ip6_hdr *ip6;
	int l3_offset;
	uint16_t type;

	ifstats->rx++;
	if (opt_bps_include_preamble)
		ifstats->rx_byte += len + DEFAULT_IFG + DEFAULT_PREAMBLE + FCS;
	else
		ifstats->rx_byte += len + FCS;

	eth = (struct ether_header *)buf;
	type = ntohs(eth->ether_type);
	if (type == ETHERTYPE_VLAN) {
		struct ether_vlan_header *vlan = (struct ether_vlan_header *)buf;
		type = ntohs(vlan->evl_proto);
		l3_offset = sizeof(struct ether_vlan_header);
	} else {
		l3_offset = sizeof(struct ether_header);
	}

	switch (type) {
	case ETHERTYPE_FLOWCONTROL:
		/* ignore FLOWCONTROL */
		ifstats->rx_flow++;
		return;
#ifdef SUPPORT_PPPOE
	case ETHERTYPE_PPPOE:
		{
			uint16_t *tp = (uint16_t *)(buf + sizeof(struct pppoe_l2));
			switch (ntohs(*tp)) {
			case PPP_IP:
				is_ipv6 = 0;
				break;
			case PPP_IPV6:
				is_ipv6 = 1;
				break;
			}
		}
		l3_offset = sizeof(struct pppoe_l2) + 2;
		if (pppoe_handler(ifno, buf) != 0) {
			ifstats->rx_arp++;
			return;
		}
		break;
#endif
	case ETHERTYPE_ARP:
		ifstats->rx_arp++;
		arp_handler(ifno, buf, l3_offset);
		return;
	case ETHERTYPE_IP:
		is_ipv6 = 0;
		break;
	case ETHERTYPE_IPV6:
		is_ipv6 = 1;
		break;
	default:
		ifstats->rx_other++;
		if (opt_debuglevel > 0) {
			printf("\r\n\r\n\r\n\r\n\r\n\r\n==== %s: len=%d ====\r\n", iface->ifname, len);
			dumpstr(buf, len, DUMPSTR_FLAGS_CRLF);
		}
		return;
	}

	if (is_ipv6) {
		/* IPv6 packet */
		ip6 = (struct ip6_hdr *)(buf + l3_offset);
		if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(ip6 + 1);	/* XXX: no support extension header */

			ifstats->rx_icmp++;

			switch (icmp6->icmp6_type) {
			case ICMP6_DST_UNREACH:
				ifstats->rx_icmpunreach++;
				return;
			case ND_REDIRECT:
				ifstats->rx_icmpredirect++;
				return;
			case ICMP6_ECHO_REQUEST:
				ifstats->rx_icmpecho++;
#if NOTYET
				icmp6echo_handler(ifno, buf, len, l3_offset);
#endif
				return;

			case ND_NEIGHBOR_SOLICIT:
				ifstats->rx_arp++;
				ndp_handler(ifno, buf, l3_offset);
				return;

			default:
				ifstats->rx_icmpother++;
				printf("icmp6 receive: type=%d, code=%d\n",
				    icmp6->icmp6_type, icmp6->icmp6_code);
				return;
			}
		}
	} else {
		/* IPv4 packet */
		ip = (struct ip *)(buf + l3_offset);
		if (ip->ip_p == IPPROTO_ICMP) {
			struct icmp *icmp = (struct icmp *)((char *)ip + ip->ip_hl * 4);

			ifstats->rx_icmp++;

			switch (icmp->icmp_type) {
			case ICMP_UNREACH:
				ifstats->rx_icmpunreach++;
				return;
			case ICMP_REDIRECT:
				ifstats->rx_icmpredirect++;
				return;
			case ICMP_ECHO:
				ifstats->rx_icmpecho++;
				icmpecho_handler(ifno, buf, len, l3_offset);
				return;
			default:
				ifstats->rx_icmpother++;
				printf("icmp receive: type=%d, code=%d, l3offset=%d\n",
				    icmp->icmp_type, icmp->icmp_code, l3_offset);
				return;
			}
		}
	}

	/* check sequence */
	struct seqdata *seqdata;
	struct sequence_record *seqrecord;
	uint64_t seq, seqflow, nskip;
	uint32_t flowid;
	struct timespec ts_delta;
	double latency;

	seqdata = (struct seqdata *)(buf + len - sizeof(struct seqdata));
	if (seqdata->magic != seq_magic) {
		/* no ipgen packet? */
		ifstats->rx_other++;
		return;
	}

	seq = seqdata->seq;
	seqrecord = seqtable_get(iface->seqtable, seq);

	if ((seqrecord == NULL) || seqrecord->seq != seq) {
		ifstats->rx_expire++;
	} else {
		timespecsub(curtime, &seqrecord->ts, &ts_delta);
		ts_delta.tv_sec &= 0xff;
		latency = ts_delta.tv_sec / 1000 + ts_delta.tv_nsec / 1000000.0;

		ifstats->latency_sum += latency;
		ifstats->latency_npkt++;
		ifstats->latency_avg = ifstats->latency_sum / ifstats->latency_npkt;

		if ((ifstats->latency_min == 0) || (ifstats->latency_min > latency))
			ifstats->latency_min = latency;
		if (ifstats->latency_max < latency)
			ifstats->latency_max = latency;

		flowid = seqrecord->flowid;
		seqflow = seqrecord->flowseq;
		if (get_flowid_max(ifno) >= flowid)
			nskip = seqcheck_receive(iface->seqchecker_perflow[flowid], seqflow);

		nskip = seqcheck_receive(iface->seqchecker, seq);
		if (opt_debuglevel > 1) {
			/* DEBUG */
			if (nskip > 2) {
				printf("\r\n\r\n\r\n\r\n\r\n\r\n<seq=%"PRIu64", nskip=%"PRIu64", tx0=%"PRIu64", tx1=%"PRIu64">",
				    seq, nskip, interface[0].sequence_tx, interface[1].sequence_tx);
				dumpstr(buf, len, DUMPSTR_FLAGS_CRLF);
			}
		}
	}
}

static void
interface_receive(int ifno)
{
	struct interface *iface = &interface[ifno];
#ifdef USE_NETMAP
	char *buf;
	unsigned int cur, n, i;
	uint16_t len;
	struct netmap_if *nifp;
	struct netmap_ring *rxring;
	struct timespec curtime;

	clock_gettime(CLOCK_MONOTONIC, &curtime);

	nifp = iface->nm_desc->nifp;
	for (i = iface->nm_desc->first_rx_ring;
	    i <= iface->nm_desc->last_rx_ring; i++) {

		rxring = NETMAP_RXRING(nifp, i);
		if (nm_ring_empty(rxring))
			continue;

		cur = rxring->cur;
		for (n = nm_ring_space(rxring); n > 0; n--, cur = nm_ring_next(rxring, cur)) {
			/* receive packet */
			buf = NETMAP_BUF(rxring, rxring->slot[cur].buf_idx);
			len = rxring->slot[cur].len;

			receive_packet(ifno, &curtime, buf, len);
		}

		rxring->head = rxring->cur = cur;
	}
#elif defined(USE_AF_XDP)
	unsigned int i, npkts;
	struct timespec curtime;
	struct ax_rx_handle handle;

	npkts = ax_wait_for_packets(iface->ax_desc, &handle);
	if (npkts == 0)
		return;

	clock_gettime(CLOCK_MONOTONIC, &curtime);

	for (i = 0; i < npkts; i++) {
		char *buf;
		uint32_t len;

		buf = ax_get_rx_buf(iface->ax_desc, &len, &handle);

		receive_packet(ifno, &curtime, buf, len);

		ax_rx_handle_advance(&handle);
	}

	ax_complete_rx(iface->ax_desc, npkts);
#endif
}

int
interface_transmit(int ifno)
{
	struct interface *iface = &interface[ifno];
	struct interface_statistics *ifstats = &iface->stats;
#ifdef USE_NETMAP
	char *buf;
	unsigned int cur, nspace, npkt, n;
#ifdef USE_MULTI_TX_QUEUE
	int i;
#endif
	struct netmap_if *nifp;
	struct netmap_ring *txring;
	int sentpkttype;

	nifp = iface->nm_desc->nifp;
	npkt = interface_need_transmit(ifno);
	npkt = MIN(npkt, opt_npkt_sync);

	clock_gettime(CLOCK_MONOTONIC, &currenttime_tx);

#ifdef USE_MULTI_TX_QUEUE
	for (i = iface->nm_desc->first_tx_ring;
	    i <= iface->nm_desc->last_tx_ring; i++) {

		txring = NETMAP_TXRING(nifp, i);
#else
		txring = NETMAP_TXRING(nifp, 0);
#endif
		nspace = nm_ring_space(txring);
		n = MIN(nspace, npkt);

		for (cur = txring->cur; n > 0; n--, cur = nm_ring_next(txring, cur)) {
			/* transmit packet */
			buf = NETMAP_BUF(txring, txring->slot[cur].buf_idx);

			sentpkttype = interface_load_transmit_packet(ifno, buf, &txring->slot[cur].len);
			if (sentpkttype < 0)
				break;

			txring->slot[cur].flags = 0;

			if (opt_bps_include_preamble)
				ifstats->tx_byte += txring->slot[cur].len + DEFAULT_IFG + DEFAULT_PREAMBLE + FCS;
			else
				ifstats->tx_byte += txring->slot[cur].len + FCS;
			ifstats->tx++;
		}
		txring->head = txring->cur = cur;
#ifdef USE_MULTI_TX_QUEUE
	}
#endif
#elif defined(USE_AF_XDP)
	unsigned int i, npkt;
	int sentpkttype;
	uint32_t idx;

	npkt = interface_need_transmit(ifno);
	npkt = MIN(npkt, opt_npkt_sync);

	idx = ax_prepare_tx(iface->ax_desc, &npkt);

	clock_gettime(CLOCK_MONOTONIC, &currenttime_tx);

	for (i = 0; i < npkt; i++) {
		char *buf;
		uint32_t *lenp;

		buf = ax_get_tx_buf(iface->ax_desc, &lenp, idx, i);

		sentpkttype = interface_load_transmit_packet(ifno, buf, (uint16_t *)lenp);
		if (sentpkttype < 0)
			break;
		if (opt_bps_include_preamble)
			ifstats->tx_byte += *lenp + DEFAULT_IFG + DEFAULT_PREAMBLE + FCS;
		else
			ifstats->tx_byte += *lenp + FCS;
		ifstats->tx++;
	}

	ax_complete_tx(iface->ax_desc, npkt);
#endif

	return 0;
}

/*
 * output json record (1line)
 *  {
 *      "time":12345678,
 *      "statistics":
 *      [
 *          {
 *              "TX":12345,"RXdrop":0,"RXdelta":1000,"TXdelta":1000,"RX":12345,"RXflow":0,"interface":"em0","TXunderrun":0,"TXrate":"100","RXrate":"100"
 *          },
 *          {
 *              "TXrate":"100","RXrate":"100","TXunderrun":0,"interface":"em1","RXflow":0,"RX":12345,"RXdelta":1000,"TXdelta":1000,"RXdrop":0,"TX":12345
 *          }
 *      ]
 *  }
 */
static int
interface_statistics_json(int ifno, char *buf, int buflen)
{
	struct interface *iface = &interface[ifno];
	struct interface_statistics *ifstats = &iface->stats;
	char buf_ipaddr[INET_ADDRSTRLEN], buf_eaddr[sizeof("00:00:00:00:00:00")];
	char buf_gwaddr[INET_ADDRSTRLEN], buf_gweaddr[sizeof("00:00:00:00:00:00")];

	inet_ntop(AF_INET, &iface->ipaddr, buf_ipaddr, sizeof(buf_ipaddr));
	inet_ntop(AF_INET, &iface->gwaddr, buf_gwaddr, sizeof(buf_gwaddr));
	ether_ntoa_r(&iface->eaddr, buf_eaddr);
	ether_ntoa_r(&iface->gweaddr, buf_gweaddr);

	return snprintf(buf, buflen,
	    "{"
	    "\"interface\":\"%s\","
	    "\"packetsize\":%"PRIu32","

	    "\"address\":\"%s\","
	    "\"macaddr\":\"%s\","
	    "\"gateway-address\":\"%s\","
	    "\"gateway-macaddr\":\"%s\","

	    "\"TX\":%"PRIu64","
	    "\"RX\":%"PRIu64","
	    "\"TXppsconfig\":%"PRIu32","
	    "\"TXpps\":%"PRIu64","
	    "\"RXpps\":%"PRIu64","
	    "\"TXbps\":%"PRIu64","
	    "\"RXbps\":%"PRIu64","
	    "\"TXunderrun\":%"PRIu64","
	    "\"RXdrop\":%"PRIu64","
	    "\"RXdropps\":%"PRIu64","
	    "\"RXdup\":%"PRIu64","
	    "\"RXreorder\":%"PRIu64","
	    "\"RXoutofrange\":%"PRIu64","

	    "\"RXdrop-perflow\":%"PRIu64","
	    "\"RXdup-perflow\":%"PRIu64","
	    "\"RXreorder-perflow\":%"PRIu64","

	    "\"RXflowcontrol\":%"PRIu64","
	    "\"RXarp\":%"PRIu64","
	    "\"RXother\":%"PRIu64","
	    "\"RXicmp\":%"PRIu64","
	    "\"RXicmpecho\":%"PRIu64","
	    "\"RXicmpunreach\":%"PRIu64","
	    "\"RXicmpredirect\":%"PRIu64","
	    "\"RXicmpother\":%"PRIu64","

	    "\"latency-max\":%.8f,"
	    "\"latency-min\":%.8f,"
	    "\"latency-avg\":%.8f"
	    "}",

	    iface->ifname,
	    iface->pktsize,
	    buf_ipaddr,
	    buf_eaddr,
	    buf_gwaddr,
	    buf_gweaddr,
	    ifstats->tx,
	    ifstats->rx,
	    iface->transmit_pps,
	    ifstats->tx_delta,
	    ifstats->rx_delta,
	    ifstats->tx_byte_delta * 8,
	    ifstats->rx_byte_delta * 8,
	    ifstats->tx_underrun,
	    ifstats->rx_seqdrop,
	    ifstats->rx_seqdrop_delta,
	    ifstats->rx_dup,
	    ifstats->rx_reorder,
	    ifstats->rx_outofrange,

	    ifstats->rx_seqdrop_flow,
	    ifstats->rx_dup_flow,
	    ifstats->rx_reorder_flow,

	    ifstats->rx_flow,
	    ifstats->rx_arp,
	    ifstats->rx_other,
	    ifstats->rx_icmp,
	    ifstats->rx_icmpecho,
	    ifstats->rx_icmpunreach,
	    ifstats->rx_icmpredirect,
	    ifstats->rx_icmpother,

	    ifstats->latency_max,
	    ifstats->latency_min,
	    ifstats->latency_avg
	);
}

#define JSON_BUFSIZE	(1024 * 16)
char jsonbuf_x[4][JSON_BUFSIZE];

static char *
build_json_statistics(unsigned int *lenp)
{
	int len;
	static uint32_t n = 0;
	char *jsonbuf;

	jsonbuf = jsonbuf_x[++n & 3];

	/* generate json statistics string */
	len = 0;
	len += snprintf(jsonbuf + len, JSON_BUFSIZE - len, "{\"apiversion\":\"1.2\"");
	len += snprintf(jsonbuf + len, JSON_BUFSIZE - len, ",\"time\":%.8f",
	    currenttime_main.tv_sec + currenttime_main.tv_nsec / 1000000000.0);

	len += snprintf(jsonbuf + len, JSON_BUFSIZE - len, ",\"statistics\":[");
	if (len <= JSON_BUFSIZE) {
		len += interface_statistics_json(0, jsonbuf + len , JSON_BUFSIZE - len);
		if (len <= JSON_BUFSIZE) {
			jsonbuf[len++] = ',';
			len += interface_statistics_json(1, jsonbuf + len, JSON_BUFSIZE - len);
			len += snprintf(jsonbuf + len, JSON_BUFSIZE - len, "]}\n");
		}
	}
	*lenp = len;

	return jsonbuf;
}

/* be careful. broadcast_json_statistics() called from signal handler */
static void
broadcast_json_statistics(char *buf, unsigned int len)
{
	if (logfd >= 0)
		write(logfd, buf, len);

	webserv_stream_broadcast(buf, len);
}

static void
sighandler_alrm(int signo __unused)
{
	static uint32_t _nhz = 0;
	uint32_t nhz;
	int i;
	uint64_t x;

	nhz = _nhz++;
	if (_nhz >= pps_hz)
		_nhz = 0;

	clock_gettime(CLOCK_MONOTONIC, &currenttime_main);

	if (opt_time) {
		struct timespec delta;
		timespecsub(&currenttime_main, &starttime_tx, &delta);
		if (delta.tv_sec >= opt_time) {
			do_quit = 1;
			return;
		}
	}

	if ((nhz + 1) >= pps_hz) {
		/*
		 * this block called 1Hz
		 */

		/* update dropcounter */
		for (i = 0; i < 2; i++) {
			struct interface *iface = &interface[i];
			struct interface_statistics *ifstats = &iface->stats;

			if (!iface->opened)
				continue;

			ifstats->rx_seqdrop =
			    seqcheck_dropcount(iface->seqchecker);
			ifstats->rx_dup =
			    seqcheck_dupcount(iface->seqchecker);
			ifstats->rx_reorder =
			    seqcheck_reordercount(iface->seqchecker);
			ifstats->rx_outofrange =
			    seqcheck_outofrangecount(iface->seqchecker);

			ifstats->rx_seqdrop_flow =
			    seqcheck_dropcount(iface->seqchecker_flowtotal);
			ifstats->rx_dup_flow =
			    seqcheck_dupcount(iface->seqchecker_flowtotal);
			ifstats->rx_reorder_flow =
			    seqcheck_reordercount(iface->seqchecker_flowtotal);


			/* update delta */
			ifstats->tx_delta = ifstats->tx - ifstats->tx_last;
			ifstats->tx_last = ifstats->tx;
			ifstats->rx_delta = ifstats->rx - ifstats->rx_last;
			ifstats->rx_last = ifstats->rx;

			ifstats->tx_byte_delta = ifstats->tx_byte - ifstats->tx_byte_last;
			ifstats->tx_byte_last = ifstats->tx_byte;
			ifstats->rx_byte_delta = ifstats->rx_byte - ifstats->rx_byte_last;
			ifstats->rx_byte_last = ifstats->rx_byte;

#if 0
			if (opt_bps_include_preamble) {
				ifstats->tx_Mbps =
				    (ifstats->tx_byte_delta +
				     (ifstats->tx_delta * (DEFAULT_IFG + DEFAULT_PREAMBLE + FCS))) *
				    8.0 / 1000 / 1000;
				ifstats->rx_Mbps =
				    (ifstats->rx_byte_delta +
				     (ifstats->rx_delta * (DEFAULT_IFG + DEFAULT_PREAMBLE + FCS))) *
				    8.0 / 1000 / 1000;
			} else {
				ifstats->tx_Mbps = (ifstats->tx_byte_delta + FCS) * 8.0 / 1000 / 1000;
				ifstats->rx_Mbps = (ifstats->rx_byte_delta + FCS) * 8.0 / 1000 / 1000;
			}
#else
			ifstats->tx_Mbps = (ifstats->tx_byte_delta) * 8.0 / 1000 / 1000;
			ifstats->rx_Mbps = (ifstats->rx_byte_delta) * 8.0 / 1000 / 1000;
#endif


			ifstats->rx_seqdrop_delta = ifstats->rx_seqdrop - ifstats->rx_seqdrop_last;
			ifstats->rx_seqdrop_last = ifstats->rx_seqdrop;
			ifstats->rx_dup_delta = ifstats->rx_dup - ifstats->rx_dup_last;
			ifstats->rx_dup_last = ifstats->rx_dup;
			ifstats->rx_reorder_delta = ifstats->rx_reorder - ifstats->rx_reorder_last;
			ifstats->rx_reorder_last = ifstats->rx_reorder;
			ifstats->rx_outofrange_delta = ifstats->rx_outofrange - ifstats->rx_outofrange_last;
			ifstats->rx_outofrange_last = ifstats->rx_outofrange;

			ifstats->rx_seqdrop_flow_delta = ifstats->rx_seqdrop_flow - ifstats->rx_seqdrop_flow_last;
			ifstats->rx_seqdrop_flow_last = ifstats->rx_seqdrop_flow;
			ifstats->rx_dup_flow_delta = ifstats->rx_dup_flow - ifstats->rx_dup_flow_last;
			ifstats->rx_dup_flow_last = ifstats->rx_dup_flow;
			ifstats->rx_reorder_flow_delta = ifstats->rx_reorder_flow - ifstats->rx_reorder_flow_last;
			ifstats->rx_reorder_flow_last = ifstats->rx_reorder_flow;
		}

		/* need to update statistics string buffer in json? */
		if ((logfd >= 0) || (webserv_need_broadcast() != 0)) {
			char *buf;
			unsigned int len;
			buf = build_json_statistics(&len);
			broadcast_json_statistics(buf, len);
		}
	}

	/* check and reset tx pps counter atomically */
	for (i = 0; i < 2; i++) {
		struct interface *iface = &interface[i];
		struct interface_statistics *ifstats = &iface->stats;
		x = ((uint64_t)iface->transmit_pps * ((uint64_t)nhz + 1) / pps_hz) -
		    ((uint64_t)iface->transmit_pps * ((uint64_t)nhz) / pps_hz);
		if (iface->transmit_enable &&
		    ((x = atomic_swap_32(&iface->transmit_txhz, x)) != 0)) {
			atomic_add_64(&ifstats->tx_underrun, x);
		}
	}

	return;
}

static void
quit(int fromsig)
{
	static int quitting = 0;
	int status = fromsig ? EXIT_FAILURE : EXIT_SUCCESS;

	if (quitting) {
		for (;;)
			pause();
		return;
	}

	quitting = 1;

	do_quit = 1;
	alarm(0);

	if (use_curses)
		itemlist_fini_term();
	else
		printf("\n");

	printf("Exiting...\n");
	fflush(stdout);

	if (!opt_txonly) {
		pthread_join(txthread0, NULL);
		pthread_join(rxthread0, NULL);
	}
	if (!opt_rxonly) {
		pthread_join(txthread1, NULL);
		pthread_join(rxthread1, NULL);
	}
	interface_close(0);
	interface_close(1);

	if (opt_rfc2544) {
		rfc2544_showresult();
		if (opt_rfc2544_output_json != NULL)
			rfc2544_showresult_json(opt_rfc2544_output_json);
	}

	if (opt_fail_if_dropped && status == EXIT_SUCCESS) {
		struct interface *iface = &interface[0];
		struct interface_statistics *ifstats = &iface->stats;

		status = ifstats->rx_seqdrop != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (fromsig)
		_exit(status);
	exit(status);
}

static void
sighandler_int(int signo __unused)
{
	quit(true);
}

static void
sighandler_tstp(int signo __unused)
{
	itemlist_fini_term();

	signal(SIGTSTP, SIG_DFL);
	killpg(0, SIGTSTP);

	itemlist_init_term();
	force_redraw_screen = 1;
}

static void
sighandler_cont(int signo __unused)
{
	signal(SIGTSTP, sighandler_tstp);
}

static void
usage(void)
{
	fprintf(stderr,
	       "\n"
	       "usage: ipgen [options]\n"
	       "	[-V <vlanid>]			use VLAN\n"
	       "	[-P]				use PPPoE\n"
	       "	-R <ifname>,<gateway-address>[,<own-address>[/<prefix>]]\n"
	       "					set RX interface\n"
	       "\n"
	       "	[-V <vlanid>]\n"
	       "	[-P]\n"
	       "	-T <ifname>,<gateway-address>[,<own-address>[/<prefix>]]\n"
	       "					set TX interface\n"
	       "\n"
	       "	-H <Hz>				specify control Hz (default: 1000)\n"
	       "	-n <npkt>			sync transmit per <npkt>\n"
	       "\n"	/* size and speed */
	       "	-s <size>			specify pktsize (IPv4:46-1500, IPv6:tcp:54-1500)\n"
	       "	-p <pps>			specify pps\n"
	       "\n"	/* L1 or L2 */
	       "	--ipg				adapt IPG (Inter Packet Gap)\n"
	       "	--burst				don't set IPG (default)\n"
	       "	--l1-bps			include IFG/PREAMBLE/FCS for bps calculation\n"
	       "	--l2-bps			don't include IFG/PREAMBLE for bps calculation (default)\n"
	       "\n"	/* L3 */
	       "	--allnet			use destination address incrementally\n"
	       "	--saddr <begin>[-<end>]		use source address range (default: TX interface address)\n"
	       "	--daddr <begin>[-<end>]		use destination address range (default: RX interface address)\n"
	       "	--sport <begin>[-<end>]		use source port range (default: 9)\n"
	       "	--dport <begin>[-<end>]		use destination port range (default: 9)\n"
	       "	--flowlist <file>		read flowlist from file\n"
	       "	--flowsort			sort flow list\n"
	       "	--flowdump			dump flow list\n"
	       "	-F <nflow>			limit <nflow>\n"
	       "\n"	/* L4 */
	       "	--tcp				generate TCP packet\n"
	       "	--udp				generate UDP packet (default)\n"
	       "	--fragment			generate fragment packet\n"
	       "\n"	/* RFC 2544 */
	       "	--rfc2544			rfc2544 test mode\n"
	       "	--rfc2544-slowstart		increase pps step-by-step (default: binary-search)\n"
	       "	--rfc2544-tolerable-error-rate <percent>\n"
	       "					rfc2544 tolerable error rate (0-100.0, default: 0.00)\n"
	       "	--rfc2544-pps-resolution <percent>\n"
	       "					rfc2544 limit of resolution of a pps (0-100.0, default: 0)\n"
	       "	--rfc2544-trial-duration <sec>	rfc2544 trial duration time (default: 60)\n"
	       "	--rfc2544-pktsize <size>[,<size>...]]\n"
	       "					test only specified pktsize. (default: 46,110,494,1006,1262,1390,1500)\n"
	       "	--rfc2544-output-json <file>	output rfc2544 results as json file format\n"
	       "	--rfc2544-interval <sec>	interval time between rfc2544 trial (default: 0)\n"
	       "	--rfc2544-warming-duration <sec>	warming time before rfc2544 trial (1-60, default: 1)\n"
	       "	--rfc2544-no-early-finish	complete each trial without finishing early\n"
	       "\n"	/* Operation control */
	       "	--nocurses			no curses mode\n"
	       "	-S <script>			autotest script\n"
	       "	-f				full-duplex mode\n"
	       "	-t <time>			send packets specified seconds and quit\n"
	       "	--fail-if-dropped		return exit status with failure if the receiver drops any packets while the last trial\n"
	       "	-L <log>			output statistics as json file format\n"
	       "	-v				verbose\n"
	       "\n"	/* Debug */
	       "	-X				packet generation benchmark\n"
	       "	-XX				packet generation benchmark with memcpy\n"
	       "	-XXX				packet generation benchmark with memcpy and cksum\n"
	       "	-D <file>			debug. dump all generated packets to <file> as tcpdump file format\n"
	       "	-d				debug. dump unknown packet\n"
	);

	exit(1);
}

static void
logging(char const *fmt, ...)
{
	struct timespec realtime_now;
	va_list ap;

	clock_gettime(CLOCK_REALTIME, &realtime_now);

	va_start(ap, fmt);
	if (!use_curses) {
		printf("%s ", timestamp(realtime_now.tv_sec));
		vprintf(fmt, ap);
		printf("\n");
	} else {
		vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	}
	va_end(ap);
#ifdef DEBUG
	va_start(ap, fmt);
	fprintf(debugfh, "%s ", timestamp(realtime_now.tv_sec));
	vfprintf(debugfh, fmt, ap);
	fprintf(debugfh, "\n");
	va_end(ap);
#endif
}


static void *
tx_thread_main(void *arg)
{
	int ifno = *(int *)arg;
	struct interface *iface = &interface[ifno];
	int i, j;

	(void)pthread_sigmask(SIG_BLOCK, &used_sigset, NULL);

	clock_gettime(CLOCK_MONOTONIC, &starttime_tx);
	while (do_quit == 0) {
		if (iface->need_reset_statistics) {
			iface->need_reset_statistics = 0;
			memset(&iface->stats, 0, sizeof(iface->stats));
			seqcheck_clear(iface->seqchecker);
			seqcheck_clear(iface->seqchecker_flowtotal);
			j = get_flownum(ifno);
			for (i = 0; i < j; i++) {
				seqcheck_clear(iface->seqchecker_perflow[i]);
			}
		}

		interface_transmit(ifno);
#ifdef USE_NETMAP
		ioctl(iface->nm_desc->fd, NIOCTXSYNC, NULL);
#endif
	}

	return NULL;
}

static void *
rx_thread_main(void *arg)
{
	int ifno = *(int *)arg;
	struct interface *iface = &interface[ifno];
	struct pollfd pollfd[1];
	int rc;

	(void)pthread_sigmask(SIG_BLOCK, &used_sigset, NULL);

	/* setup poll */
	memset(pollfd, 0, sizeof(pollfd));
#ifdef USE_NETMAP
	pollfd[0].fd = iface->nm_desc->fd;
#elif defined(USE_AF_XDP)
	pollfd[0].fd = ax_get_fd(iface->ax_desc);
#endif

	while (do_quit == 0) {
		pollfd[0].events = POLLIN;
		pollfd[0].revents = 0;

		rc = poll(pollfd, 1, 100);
		if (rc < 0) {
			if (errno == EINTR)
				continue;

			printf("poll: %s\n", strerror(errno));
			continue;
		}

		if (pollfd[0].revents & POLLIN)
			interface_receive(ifno);
	}

	return NULL;
}



static void
genscript_play(void)
{
	static u_int nth_test = 0;
	static int period_left = 0;
	struct genscript_item *genitem;

	if (do_quit)
		return;

	period_left--;
	if (period_left <= 0) {
		do {
			genitem = genscript_get_item(genscript, nth_test);
			nth_test++;
			if (genitem == NULL) {
				quit(false);
				return;
			}

			period_left = genitem->period;

			switch (genitem->cmd) {
			case GENITEM_CMD_RESET:
				logging("script: reset ifstats");
				statistics_clear();
				break;
			case GENITEM_CMD_NOP:
				break;

			case GENITEM_CMD_TX0SET:
				logging("script: %s: packet size = %u, pps = %u",
				    interface[0].ifname,
				    genitem->pktsize, genitem->pps);
				setpktsize(0, genitem->pktsize);
				setpps(0, genitem->pps);
				break;
			case GENITEM_CMD_TX1SET:
				logging("script: %s: packet size = %u, pps = %u",
				    interface[1].ifname,
				    genitem->pktsize, genitem->pps);
				setpktsize(1, genitem->pktsize);
				setpps(1, genitem->pps);
				break;
			}

		} while (period_left == 0);
	}
}

static void
control_tty_handler(int fd, struct itemlist *itemlist)
{
#ifdef __FreeBSD__
	sigset_t sigalrmset;
#endif
	int c, grabbed;

#ifdef __FreeBSD__
	/*
	 * for freebsd bug:
	 * with high frequency SIGALRM, getch() cannot tread KEYPAD
	 */
	sigemptyset(&sigalrmset);
	sigaddset(&sigalrmset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigalrmset, NULL);
#endif
	c = getch();
#ifdef __FreeBSD__
	sigprocmask(SIG_UNBLOCK, &sigalrmset, NULL);
#endif

	if (opt_rfc2544) {
		if ((c == 'q') || (c == 'Q'))
			quit(false);

		if (c != 0x0c) {	/* ^L */
			/* you can exit from RFC2544 mode by '!' for debug */
			if (c == '!') {
				opt_rfc2544 = 0;
				logging("exiting rfc2544 mode");
				return;
			}
			logging("cannot control in rfc2544 mode");
			return;
		}
	}

	grabbed = itemlist_ttyhandler(itemlist, c);

	if (grabbed)
		return;

	switch (c) {
	case 'q':
	case 'Q':
		quit(false);
		break;

	case 'z':
	case 'Z':
		statistics_clear();
		break;

#if 0
	case '\0':
		seqcheck_dump(interface[1].seqchecker);
		seqcheck_dump(interface[0].seqchecker);
		for (i = 0; i < 100; i++)
			printf("\n");
		break;
#endif
	}
}


/*
 * RFC2544 test sequence
 */
struct rfc2544_work {
	unsigned int pktsize;
	unsigned int minpps;
	unsigned int maxpps;
	unsigned int ppsresolution;
	unsigned int limitpps;
	unsigned int curpps;
	unsigned int prevpps;
	unsigned int maxup;
};

#define RFC2544_MAXTESTNUM	64
struct rfc2544_work rfc2544_work[RFC2544_MAXTESTNUM];
static u_int rfc2544_ntest = 0;
static u_int rfc2544_nthtest = 0;

typedef enum {
	RFC2544_START,
	RFC2544_WARMUP0,
	RFC2544_WARMUP,
	RFC2544_RESETTING0,
	RFC2544_RESETTING,
	RFC2544_INTERVAL0,
	RFC2544_INTERVAL,
	RFC2544_WARMING0,
	RFC2544_WARMING,
	RFC2544_MEASURING0,
	RFC2544_MEASURING,
	RFC2544_DONE0,
	RFC2544_DONE
} rfc2544_state_t;

static void
rfc2544_add_test(uint64_t maxlinkspeed, unsigned int pktsize)
{
	struct rfc2544_work *work = &rfc2544_work[rfc2544_ntest];

	if (rfc2544_ntest >= RFC2544_MAXTESTNUM) {
		fprintf(stderr, "Too many rfc2544 test (max 64). pktsize=%u ignored\n", pktsize);
		return;
	}
	if ((pktsize < (64 - ETHHDRSIZE - FCS)) || (pktsize > 2048 - ETHHDRSIZE - FCS)) {
		fprintf(stderr, "Illegal packet size: %d. ignored\n", pktsize);
		return;
	}

	memset(work, 0, sizeof(*work));

	work->pktsize = pktsize;
	work->minpps = 1;
	work->maxpps = maxlinkspeed / 8 / (pktsize + 18 + DEFAULT_IFG + DEFAULT_PREAMBLE);
	rfc2544_ntest++;
}

static void
rfc2544_load_default_test(uint64_t maxlinkspeed)
{
	rfc2544_ntest = 0;	/* clear table */
	rfc2544_add_test(maxlinkspeed, 64 - ETHHDRSIZE - FCS);
	rfc2544_add_test(maxlinkspeed, 128 - ETHHDRSIZE - FCS);
	rfc2544_add_test(maxlinkspeed, 512 - ETHHDRSIZE - FCS);
	rfc2544_add_test(maxlinkspeed, 1024 - ETHHDRSIZE - FCS);
	rfc2544_add_test(maxlinkspeed, 1280 - ETHHDRSIZE - FCS);
	rfc2544_add_test(maxlinkspeed, 1408 - ETHHDRSIZE - FCS);
	rfc2544_add_test(maxlinkspeed, 1518 - ETHHDRSIZE - FCS);
}

static void
rfc2544_calc_param(uint64_t maxlinkspeed)
{
	u_int i;

	for (i = 0; i < rfc2544_ntest; i++) {
		rfc2544_work[i].maxpps = maxlinkspeed / 8 / (rfc2544_work[i].pktsize + 18 + DEFAULT_IFG + DEFAULT_PREAMBLE);
	}
}

void
rfc2544_showresult(void)
{
	double mbps, tmp;
	unsigned int pps, linkspeed;
	u_int i, j;

	/*
	 * [example]
	 *
	 * #1G
	 *
	 *	framesize|0M  100M 200M 300M 400M 500M 600M 700M 800M 900M 1Gbps
	 *	---------+----+----+----+----+----+----+----+----+----+----+
	 *	      64 |#######################                            ###.##Mbps, #######/########pps, ###.##%
	 *	     128 |#############################                      ###.##Mbps, #######/########pps, ###.##%
	 *	     256 |#############################################      ###.##Mbps, #######/########pps, ###.##%
	 *	     512 |#################################################  ###.##Mbps, #######/########pps, ###.##%
	 *	    1024 |################################################## ###.##Mbps, #######/########pps, ###.##%
	 *	    1280 |################################################## ###.##Mbps, #######/########pps, ###.##%
	 *	    1408 |################################################## ###.##Mbps, #######/########pps, ###.##%
	 *	    1518 |################################################## ###.##Mbps, #######/########pps, ###.##%
	 *	
	 *	framesize|0   |100k|200k|300k|400k|500k|600k|700k|800k|900k|1.0m|1.1m|1.2m|1.3m|1.4m|1.5m pps
	 *	---------+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	 *	      64 |#################################################################          #######/########pps, ###.##%
	 *	     128 |#################################                                          #######/########pps, ###.##%
	 *	     256 |#################                                                          #######/########pps, ###.##%
	 *	     512 |########                                                                   #######/########pps, ###.##%
	 *	    1024 |#####                                                                      #######/########pps, ###.##%
	 *	    1280 |##                                                                         #######/########pps, ###.##%
	 *	    1408 |#                                                                          #######/########pps, ###.##%
	 *	    1518 |#                                                                          #######/########pps, ###.##%
	 *
	 *
	 * #10G
	 *
	 *	framesize|0G  1G   2G   3G   4G   5G   6G   7G   8G   9G   10Gbps
	 *	---------+----+----+----+----+----+----+----+----+----+----+
	 *	      64 |#######################                            ####.##Mbps, ########/#########pps, ###.##%
	 *	     128 |#############################                      ####.##Mbps, ########/#########pps, ###.##%
	 *	     256 |#############################################      ####.##Mbps, ########/#########pps, ###.##%
	 *	     512 |#################################################  ####.##Mbps, ########/#########pps, ###.##%
	 *	    1024 |################################################## ####.##Mbps, ########/#########pps, ###.##%
	 *	    1280 |################################################## ####.##Mbps, ########/#########pps, ###.##%
	 *	    1408 |################################################## ####.##Mbps, ########/#########pps, ###.##%
	 *	    1518 |################################################## ####.##Mbps, ########/#########pps, ###.##%
	 *	
	 *	framesize|0   |1m  |2m  |3m  |4m  |5m  |6m  |7m  |8m  |9m  |10m |11m |12m |13m |14m |15m pps
	 *	---------+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	 *	      64 |#################################################################          ########/#########pps, ###.##%
	 *	     128 |#################################                                          ########/#########pps, ###.##%
	 *	     256 |#################                                                          ########/#########pps, ###.##%
	 *	     512 |########                                                                   ########/#########pps, ###.##%
	 *	    1024 |#####                                                                      ########/#########pps, ###.##%
	 *	    1280 |##                                                                         ########/#########pps, ###.##%
	 *	    1408 |#                                                                          ########/#########pps, ###.##%
	 *	    1518 |#                                                                          ########/#########pps, ###.##%
	 */


	/* check link speed. 1G or 10G? */
	tmp = 0 ;
	for (i = 0; i < rfc2544_ntest; i++) {
		struct rfc2544_work *work = &rfc2544_work[i];
		mbps = calc_mbps_l1(work->pktsize, work->curpps);
		if (tmp < mbps)
			tmp = mbps;
	}
	if (tmp > 10000.0)
		linkspeed = 100; /* 100G */
	else if (tmp > 1000.0)
		linkspeed = 10;	/* 10G */
	else
		linkspeed = 1;	/* 1G */


	printf("\n");
	printf("\n");
	printf("rfc2544 tolerable error rate: %.4f%%\n", opt_rfc2544_tolerable_error_rate);
	printf("rfc2544 trial duration: %d sec\n", opt_rfc2544_trial_duration);
	printf("rfc2544 pps resolution: %.4f%%\n", opt_rfc2544_ppsresolution);
	printf("rfc2544 interval: %d sec\n", opt_rfc2544_interval);
	printf("rfc2544 warming duration: %d sec\n", opt_rfc2544_warming_duration);
	printf("\n");

	if (linkspeed == 100)
		printf("framesize|0G  10G  20G  30G  40G  50G  60G  70G  80G  90G  100Gbps\n");
	else if (linkspeed == 10)
		printf("framesize|0G  1G   2G   3G   4G   5G   6G   7G   8G   9G   10Gbps\n");
	else
		printf("framesize|0M  100M 200M 300M 400M 500M 600M 700M 800M 900M 1Gbps\n");
	printf("---------+----+----+----+----+----+----+----+----+----+----+\n");

	for (i = 0; i < rfc2544_ntest; i++) {
		struct rfc2544_work *work = &rfc2544_work[i];
		printf("%8u |", work->pktsize + 18);

		mbps = calc_mbps(work->pktsize, work->curpps);
		for (j = 0; j < mbps / 20 / linkspeed; j++)
			printf("#");
		for (; j < 51; j++)
			printf(" ");

		if (linkspeed == 100)
			printf("%9.2fMbps, %9u/%9upps, %6.2f%%\n", mbps, work->curpps, work->limitpps,
			    work->curpps * 100.0 / work->limitpps);
		else if (linkspeed == 10)
			printf("%8.2fMbps, %8u/%8upps, %6.2f%%\n", mbps, work->curpps, work->limitpps,
			    work->curpps * 100.0 / work->limitpps);
		else
			printf("%7.2fMbps, %7u/%7upps, %6.2f%%\n", mbps, work->curpps, work->limitpps,
			    work->curpps * 100.0 / work->limitpps);
	}
	printf("\n");

	if (linkspeed == 100)
		printf("framesize|0   |10m |20m |30m |40m |50m |60m |70m |80m |90m |100m|110m|120m|130m|140m|150m pps\n");
	else if (linkspeed == 10)
		printf("framesize|0   |1m  |2m  |3m  |4m  |5m  |6m  |7m  |8m  |9m  |10m |11m |12m |13m |14m |15m pps\n");
	else
		printf("framesize|0   |100k|200k|300k|400k|500k|600k|700k|800k|900k|1.0m|1.1m|1.2m|1.3m|1.4m|1.5m pps\n");
	printf("---------+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+\n");
	for (i = 0; i < rfc2544_ntest; i++) {
		struct rfc2544_work *work = &rfc2544_work[i];

		printf("%8u |", work->pktsize + 18);

		pps = work->curpps;
		for (j = 0; j < pps / 20000 / linkspeed; j++)
			printf("#");
		for (; j < 75; j++)
			printf(" ");

		if (linkspeed == 100)
			printf("%9u/%9upps, %6.2f%%\n", work->curpps, work->limitpps,
			    work->curpps * 100.0 / work->limitpps);
		else if (linkspeed == 10)
			printf("%8u/%8upps, %6.2f%%\n", work->curpps, work->limitpps,
			    work->curpps * 100.0 / work->limitpps);
		else
			printf("%7u/%7upps, %6.2f%%\n", work->curpps, work->limitpps,
			    work->curpps * 100.0 / work->limitpps);
	}
	printf("\n");
}

void
rfc2544_showresult_json(char *filename)
{
	double bps;
	u_int i;
	FILE *fp;

	/*
	 * [example]
	 * {
	 *     "framesize": {
	 *         "64": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "128": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "256": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "512": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "1024": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "1280": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "1408": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         },
	 *         "1518": {
	 *             "bps": "##.######",
	 *             "curpps": "##",
	 *             "limitpps": "##"
	 *         }
	 *     }
	 * }
	 *
	 */

	fp = fopen(filename, "w");
	fprintf(fp, "{");
	fprintf(fp, "\"framesize\":{");
	for (i = 0; i < rfc2544_ntest; i++) {
		struct rfc2544_work *work = &rfc2544_work[i];
		if (0 < i)
			fprintf(fp, ",");
		fprintf(fp, "\"%u\":", work->pktsize + 18);
		fprintf(fp, "{");
		bps = calc_bps(work->pktsize, work->curpps);
		fprintf(fp, "\"bps\":\"%f\",", bps);
		fprintf(fp, "\"curpps\":\"%u\",", work->curpps);
		fprintf(fp, "\"limitpps\":\"%u\"", work->limitpps);
		fprintf(fp, "}");
	}
	fprintf(fp, "}");
	fprintf(fp, "}");
	fclose(fp);
}

static int
rfc2544_down_pps(void)
{
	struct rfc2544_work *work = &rfc2544_work[rfc2544_nthtest];

	if ((work->curpps - work->ppsresolution) <= work->minpps) {
		work->curpps = work->minpps;
		return 1;
	}

	work->prevpps = work->curpps;
	work->maxpps = work->curpps;
	work->curpps = (work->minpps + work->maxpps) / 2;

	return 0;
}

static int
rfc2544_up_pps(void)
{
	struct rfc2544_work *work = &rfc2544_work[rfc2544_nthtest];
	unsigned int nextpps;


	if ((work->curpps + work->ppsresolution - 1) >= work->maxpps)
		return 1;

	work->prevpps = work->curpps;
	work->minpps = work->curpps;

	nextpps = (work->minpps + work->maxpps + 1) / 2;
	if ((nextpps - work->curpps) > work->maxup)
		nextpps = work->curpps + work->maxup;
	work->curpps = nextpps;

	if (work->curpps < work->minpps)
		return 1;

	return 0;
}

static void
rfc2544_test(void)
{
	struct rfc2544_work *work = &rfc2544_work[rfc2544_nthtest];
	static rfc2544_state_t state = RFC2544_START;
	static struct timespec statetime;
	int measure_done, do_down_pps;

	switch (state) {
	case RFC2544_START:
		logging("start rfc2544 test mode. trial-duration is %d sec and interval is %d sec. warming up...",
		    opt_rfc2544_trial_duration, opt_rfc2544_interval);

		/* disable transmit */
		transmit_set(0, 0);
		transmit_set(1, 1);
		setpps(0, 0);
		setpps(1, 10000);
		setpktsize(0, 0);
		setpktsize(1, 0);
		state = RFC2544_WARMUP0;
		break;

	case RFC2544_WARMUP0:
		memcpy(&statetime, &currenttime_main, sizeof(struct timeval));
		statetime.tv_sec += 3;	/* wait 3sec */
		state = RFC2544_WARMUP;
		break;
	case RFC2544_WARMUP:
		if (timespeccmp(&currenttime_main, &statetime, <))
			break;
		state = RFC2544_RESETTING0;
		break;

	case RFC2544_RESETTING0:
		transmit_set(1, 0);
		statistics_clear();

		work->limitpps = work->maxpps;

		work->ppsresolution =
		    work->limitpps * opt_rfc2544_ppsresolution / 100.0;
		if (work->ppsresolution < 1)
		    work->ppsresolution = 1;

		if (opt_rfc2544_slowstart)
			work->maxup = work->maxpps / 10;
		else
			work->maxup = work->maxpps / 2;

		work->prevpps = 0;
		work->curpps = work->maxup;

		memcpy(&statetime, &currenttime_main, sizeof(struct timeval));
		statetime.tv_sec += 2;	/* wait 2sec */
		state = RFC2544_RESETTING;
		break;

	case RFC2544_RESETTING:
		statistics_clear();
		if (timespeccmp(&currenttime_main, &statetime, <))
			break;

		/* enable transmit */
		setpps(1, work->curpps);
		setpktsize(1, work->pktsize);
		statistics_clear();
		transmit_set(1, 1);

		state = RFC2544_WARMING0;
		break;

	case RFC2544_INTERVAL0:
		transmit_set(1, 0);
		statistics_clear();
		memcpy(&statetime, &currenttime_main, sizeof(struct timeval));
		statetime.tv_sec += opt_rfc2544_interval;
		logging("interval: wait %d sec.", opt_rfc2544_interval);

		state = RFC2544_INTERVAL;
		break;

	case RFC2544_INTERVAL:
		if (timespeccmp(&currenttime_main, &statetime, <))
			break;

		state = RFC2544_WARMING0;
		break;

	case RFC2544_WARMING0:
		transmit_set(1, 1);
		statistics_clear();
		logging("warming: %d sec, pktsize %u, pps %u, %.2fMbps [%.2fMbps:%.2fMbps]",
		    opt_rfc2544_warming_duration,
		    work->pktsize,
		    work->curpps,
		    calc_mbps(work->pktsize, work->curpps),
		    calc_mbps(work->pktsize, work->minpps),
		    calc_mbps(work->pktsize, work->maxpps));

		memcpy(&statetime, &currenttime_main, sizeof(struct timeval));
		statetime.tv_sec += opt_rfc2544_warming_duration;
		state = RFC2544_WARMING;
		break;

	case RFC2544_WARMING:
		if (timespeccmp(&currenttime_main, &statetime, <))
			break;

		statistics_clear();
		state = RFC2544_MEASURING0;
		break;

	case RFC2544_MEASURING0:
		if (work->prevpps) {
			logging("measuring pktsize %u, pps %u->%u, %.2f->%.2fMbps [%.2fMbps:%.2fMbps]",
			    work->pktsize,
			    work->prevpps,
			    work->curpps,
			    calc_mbps(work->pktsize, work->prevpps),
			    calc_mbps(work->pktsize, work->curpps),
			    calc_mbps(work->pktsize, work->minpps),
			    calc_mbps(work->pktsize, work->maxpps));
		} else {
			logging("measuring pktsize %d, pps %d (%.2fMbps)",
			    work->pktsize,
			    work->curpps,
			    calc_mbps(work->pktsize, work->curpps));
		}

		memcpy(&statetime, &currenttime_main, sizeof(struct timeval));
		statetime.tv_sec += opt_rfc2544_trial_duration;
		state = RFC2544_MEASURING;
		break;

	case RFC2544_MEASURING:
		measure_done = 0;
		do_down_pps = 0;

		if (!opt_rfc2544_early_finish && timespeccmp(&currenttime_main, &statetime, <))
			break;

		if ((interface[0].stats.rx != 0) &&
		    (((interface[0].stats.rx_seqdrop * 100.0) / interface[0].stats.rx) > opt_rfc2544_tolerable_error_rate)) {

			do_down_pps = 1;
			DEBUGLOG("RFC2544: pktsize=%d, pps=%d (%.2fMbps), rx=%"PRIu64", drop=%"PRIu64", drop-rate=%.3f\n",
			    work->pktsize,
			    work->curpps,
			    calc_mbps(work->pktsize, work->curpps),
			    interface[0].stats.rx,
			    interface[0].stats.rx_seqdrop,
			    interface[0].stats.rx_seqdrop * 100.0 / interface[0].stats.rx);
			DEBUGLOG("RFC2544: down pps\n");

		} else if (timespeccmp(&currenttime_main, &statetime, >)) {
			if (interface[0].stats.rx == 0) {
				do_down_pps = 1;
				DEBUGLOG("RFC2544: pktsize=%d, pps=%d, no packet received. down pps\n",
				    work->pktsize,
				    work->curpps);
			} else {
				/* pause frame workaround */
				const uint64_t pause_detect_threshold = 10000; /* XXXX */
				DEBUGLOG("RFC2544: tx_underrun=%lu, pause_detect_threshold=%lu, tx=%lu, tolerable_error_rate=%.4f\n",
				    interface[1].stats.tx_underrun, pause_detect_threshold, interface[1].stats.tx, opt_rfc2544_tolerable_error_rate);
				if (interface[1].stats.tx_underrun > pause_detect_threshold
				    && (((interface[1].stats.tx_underrun * 100.0) / interface[1].stats.tx)
					> opt_rfc2544_tolerable_error_rate)) {
					do_down_pps = 1;
					DEBUGLOG("RFC2544: pktsize=%d, pps=%d, pause frame workaround. down pps\n",
					    work->pktsize,
					    work->curpps);
				} else if ((interface[0].stats.rx * 100.0 / interface[1].stats.tx) < opt_rfc2544_tolerable_error_rate) {
					do_down_pps = 1;
					DEBUGLOG("RFC2544: pktsize=%d, pps=%d, tx=%"PRIu64", rx=%"PRIu64", enough packets not received. down pps\n",
					    work->pktsize,
					    work->curpps,
					    interface[1].stats.tx, interface[0].stats.rx);
				} else {
					/* no drop. OK! */
					measure_done = rfc2544_up_pps();
					if (!measure_done) {
						DEBUGLOG("RFC2544: pktsize=%d, pps=%d, no drop. up pps\n",
						    work->pktsize,
						    work->curpps);

						setpps(1, work->curpps);
						state = opt_rfc2544_interval > 0 ? RFC2544_INTERVAL0 : RFC2544_WARMING0;
					}
				}
			}
		}

		if (do_down_pps) {
			measure_done = rfc2544_down_pps();
			if (!measure_done) {
				setpps(1, work->curpps);
				transmit_set(1, 0);
				statistics_clear();
				memcpy(&statetime, &currenttime_main, sizeof(struct timeval));
				statetime.tv_sec += opt_rfc2544_interval;
				logging("interval: wait %d sec.", opt_rfc2544_interval);
				state = RFC2544_INTERVAL;
			}
		}

		if (measure_done) {
			logging("done. pktsize %d, maximum pps %d (%.2fMbps)",
			    work->pktsize,
			    work->curpps,
			    calc_mbps(work->pktsize, work->curpps));

			rfc2544_nthtest++;
			if (rfc2544_nthtest >= rfc2544_ntest) {
				logging("complete");
				state = RFC2544_DONE0;
			} else {
				state = RFC2544_RESETTING0;
			}
		}
		break;

	case RFC2544_DONE0:
		transmit_set(1, 0);
		state = RFC2544_DONE;
		break;

	case RFC2544_DONE:
		do_quit = 1;
		break;
	}

}

static void
nocurses_update(void)
{
#if 0
	static struct std_output_info {
		uint64_t drop, drop_flow;
	} output_last[2];
	int i;

#define IF_UPDATE(a, b)	if (((a) != (b)) && (((a) = (b)), nupdate++, 1))
	for (i = 0; i < 2; i++) {
		IF_UPDATE(output_last[i].drop, interface[i].stats.rx_seqdrop)
			logging("%s.drop=%lu", interface[i].ifname, interface[i].stats.rx_seqdrop);
		IF_UPDATE(output_last[i].drop_flow, interface[i].stats.rx_seqdrop_flow)
			logging("%s.drop-perflow=%lu", interface[i].ifname, interface[i].stats.rx_seqdrop_flow);
	}
#endif
}

/*
 * control_interval() will be called DISPLAY_UPDATE_HZ
 */
static void
control_interval(struct itemlist *itemlist)
{
	static unsigned int ninterval = 0;
	static unsigned int ntwiddle = 0;

	const char *twiddle0[12] = {
		">   >>>  ",
		">>   >>> ",
		">>>   >>>",
		" >>>   >>",
		"  >>>   >",
		"   >>>   ",
		">   >>>  ",
		">>   >>> ",
		">>>   >>>",
		" >>>   >>",
		"  >>>   >",
		"   >>>    "
	};
	const char *twiddle1[12] = {
		"  <<<   <",
		" <<<   <<",
		"<<<   <<<",
		"<<   <<< ",
		"<   <<<  ",
		"   <<<   ",
		"  <<<   <",
		" <<<   <<",
		"<<<   <<<",
		"<<   <<< ",
		"<   <<<  ",
		"   <<<   "
	};

	if (itemlist != NULL) {
		if (ntwiddle >= 12)
			ntwiddle = 0;

		if (interface[0].transmit_pps && interface[0].transmit_enable) {
			strcpy(interface[0].twiddle, twiddle0[ntwiddle]);
		} else {
			interface[0].twiddle[0] = '\0';
		}

		if (interface[1].transmit_pps && interface[1].transmit_enable) {
			strcpy(interface[1].twiddle, twiddle1[ntwiddle]);
		} else {
			interface[1].twiddle[0] = '\0';
		}
	}

	if ((genscript != NULL) && (ninterval == 0)) {
		/* call once every second */
		genscript_play();
	}

	if (opt_rfc2544) {
		rfc2544_test();
	}

	if (use_curses) {
		itemlist_update(itemlist, 0);
	} else if (ninterval == 0) {
		nocurses_update();
	}

#if 1
	if (ninterval & 1)
		ntwiddle++;
#elif 0
	switch (ninterval) {
	case 0:
	case DISPLAY_UPDATE_HZ / 2:
		ntwiddle++;
		break;
	}
#else
	ntwiddle++;
#endif

	if (++ninterval >= DISPLAY_UPDATE_HZ)
		ninterval = 0;
}

static int
itemlist_callback_burst_steady(struct itemlist *itemlist __unused, struct item *item, void *refptr __unused)
{
	switch (item->id) {
	case ITEMLIST_ID_BUTTON_BURST:
		ipg_enable(0);
		break;

	case ITEMLIST_ID_BUTTON_STEADY:
		ipg_enable(1);
		break;
	}

	return 0;
}

static int
itemlist_callback_l1_l2(struct itemlist *itemlist, struct item *item, void *refptr __unused)
{
	switch (item->id) {
	case ITEMLIST_ID_BUTTON_BPS_L1:
		opt_bps_include_preamble = 1;
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BPS_L1, "*");
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BPS_L2, NULL);
		snprintf(bps_desc, sizeof(bps_desc), "(include PRE+FCS+IFG)");
		break;

	case ITEMLIST_ID_BUTTON_BPS_L2:
		opt_bps_include_preamble = 0;
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BPS_L1, NULL);
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BPS_L2, "*");
		snprintf(bps_desc, sizeof(bps_desc), "(include FCS)");
		break;
	}

	update_transmit_Mbps(0);
	update_transmit_Mbps(1);

	return 0;
}

static int
itemlist_callback_nflow(struct itemlist *itemlist __unused, struct item *item __unused, void *refptr)
{
	int *nflow_test;

	nflow_test = (int *)refptr;
	if (*nflow_test < 1)
		*nflow_test = 1;

	if (*nflow_test > get_flownum(0))
		*nflow_test = get_flownum(0);

	return 0;
}

static int
itemlist_callback_pktsize(struct itemlist *itemlist __unused, struct item *item, void *refptr)
{
	uint32_t *pktsize;
	int ifno;

	pktsize = (uint32_t *)refptr;
	if (*pktsize < min_pktsize)
		*pktsize = min_pktsize;
	if (*pktsize > 1500)
		*pktsize = 1500;

	switch (item->id) {
	default:
	case ITEMLIST_ID_IF0_PKTSIZE:
		ifno = 0;
		break;
	case ITEMLIST_ID_IF1_PKTSIZE:
		ifno = 1;
		break;
	}

	interface[ifno].pktsize = *pktsize;
	update_transmit_Mbps(ifno);

	return 0;
}

static int
itemlist_callback_pps(struct itemlist *itemlist __unused, struct item *item, void *refptr)
{
	uint32_t *pps;
	int ifno;

	pps = (uint32_t *)refptr;

	switch (item->id) {
	default:
	case ITEMLIST_ID_IF0_PPS:
		ifno = 0;
		break;
	case ITEMLIST_ID_IF1_PPS:
		ifno = 1;
		break;
	}

	interface[ifno].transmit_pps = *pps;
	update_transmit_Mbps(ifno);

	return 0;
}

static int
itemlist_callback_startstop(struct itemlist *itemlist __unused, struct item *item, void *refptr __unused)
{
	switch (item->id) {
	case ITEMLIST_ID_IF0_START:
		transmit_set(0, 1);
		break;
	case ITEMLIST_ID_IF0_STOP:
		transmit_set(0, 0);
		break;

	case ITEMLIST_ID_IF1_START:
		transmit_set(1, 1);
		break;
	case ITEMLIST_ID_IF1_STOP:
		transmit_set(1, 0);
		break;
	}

	return 0;
}

static void
control_init_items(struct itemlist *itemlist)
{
	static char ipgen_api[16];

	itemlist_register_item(itemlist, ITEMLIST_ID_IPGEN_VERSION, NULL, ipgen_version);
#ifdef USE_NETMAP
	snprintf(ipgen_api, sizeof(ipgen_api), "netmap:%d", NETMAP_API);
#else
	snprintf(ipgen_api, sizeof(ipgen_api), "XDP");
#endif
	itemlist_setvalue(itemlist, ITEMLIST_ID_IPGEN_API, &ipgen_api);

#define REG(name, arg2, arg3)	itemlist_register_item(itemlist, ITEMLIST_ID_ ## name, (arg2), (arg3))

	REG(IFNAME0, NULL, interface[0].decorated_ifname);
	REG(IFNAME1, NULL, interface[1].decorated_ifname);
	REG(TWIDDLE0, NULL, interface[0].twiddle);
	REG(TWIDDLE1, NULL, interface[1].twiddle);

	struct interface_statistics *ifstats0 = &interface[0].stats;
	struct interface_statistics *ifstats1 = &interface[1].stats;

	REG(IF0_TX, NULL, &ifstats0->tx);
	REG(IF1_TX, NULL, &ifstats1->tx);
	REG(IF0_TX_OTHER, NULL, &ifstats0->tx_other);
	REG(IF1_TX_OTHER, NULL, &ifstats1->tx_other);
	REG(IF0_TX_UNDERRUN, NULL, &ifstats0->tx_underrun);
	REG(IF1_TX_UNDERRUN, NULL, &ifstats1->tx_underrun);
	REG(IF0_RX, NULL, &ifstats0->rx);
	REG(IF1_RX, NULL, &ifstats1->rx);
	REG(IF0_RX_DROP, NULL, &ifstats0->rx_seqdrop);
	REG(IF1_RX_DROP, NULL, &ifstats1->rx_seqdrop);
	REG(IF0_RX_DUP, NULL, &ifstats0->rx_dup);
	REG(IF1_RX_DUP, NULL, &ifstats1->rx_dup);
	REG(IF0_RX_REORDER, NULL, &ifstats0->rx_reorder);
	REG(IF1_RX_REORDER, NULL, &ifstats1->rx_reorder);
	REG(IF0_RX_REORDER_FLOW, NULL, &ifstats0->rx_reorder_flow);
	REG(IF1_RX_REORDER_FLOW, NULL, &ifstats1->rx_reorder_flow);
	REG(IF0_RX_OUTOFRANGE, NULL, &ifstats0->rx_outofrange);
	REG(IF1_RX_OUTOFRANGE, NULL, &ifstats1->rx_outofrange);
	REG(IF0_RX_FLOW, NULL, &ifstats0->rx_flow);
	REG(IF1_RX_FLOW, NULL, &ifstats1->rx_flow);
	REG(IF0_RX_ARP, NULL, &ifstats0->rx_arp);
	REG(IF1_RX_ARP, NULL, &ifstats1->rx_arp);
	REG(IF0_RX_ICMP, NULL, &ifstats0->rx_icmp);
	REG(IF1_RX_ICMP, NULL, &ifstats1->rx_icmp);
#if 0
	REG(IF0_RX_ICMPECHO, NULL, &ifstats0->rx_icmpecho);
	REG(IF1_RX_ICMPECHO, NULL, &ifstats1->rx_icmpecho);
	REG(IF0_RX_ICMPUNREACH, NULL, &ifstats0->rx_icmpunreach);
	REG(IF1_RX_ICMPUNREACH, NULL, &ifstats1->rx_icmpunreach);
	REG(IF0_RX_ICMPREDIRECT, NULL, &ifstats0->rx_icmpredirect);
	REG(IF1_RX_ICMPREDIRECT, NULL, &ifstats1->rx_icmpredirect);
	REG(IF0_RX_ICMPOTHER, NULL, &ifstats0->rx_icmpother);
	REG(IF1_RX_ICMPOTHER, NULL, &ifstats1->rx_icmpother);
#endif
	REG(IF0_RX_OTHER, NULL, &ifstats0->rx_other);
	REG(IF1_RX_OTHER, NULL, &ifstats1->rx_other);

	REG(IF0_TX_DELTA, NULL, &ifstats0->tx_delta);
	REG(IF1_TX_DELTA, NULL, &ifstats1->tx_delta);
	REG(IF0_TX_BYTE_DELTA, NULL, &ifstats0->tx_byte_delta);
	REG(IF1_TX_BYTE_DELTA, NULL, &ifstats1->tx_byte_delta);
	REG(IF0_TX_MBPS, NULL, &ifstats0->tx_Mbps);
	REG(IF1_TX_MBPS, NULL, &ifstats1->tx_Mbps);
	REG(IF0_RX_DELTA, NULL, &ifstats0->rx_delta);
	REG(IF1_RX_DELTA, NULL, &ifstats1->rx_delta);
	REG(IF0_RX_BYTE_DELTA, NULL, &ifstats0->rx_byte_delta);
	REG(IF1_RX_BYTE_DELTA, NULL, &ifstats1->rx_byte_delta);
	REG(IF0_RX_MBPS, NULL, &ifstats0->rx_Mbps);
	REG(IF1_RX_MBPS, NULL, &ifstats1->rx_Mbps);

	REG(IF0_LATENCY_MIN, NULL, &ifstats0->latency_min);
	REG(IF1_LATENCY_MIN, NULL, &ifstats1->latency_min);
	REG(IF0_LATENCY_MAX, NULL, &ifstats0->latency_max);
	REG(IF1_LATENCY_MAX, NULL, &ifstats1->latency_max);
	REG(IF0_LATENCY_AVG, NULL, &ifstats0->latency_avg);
	REG(IF1_LATENCY_AVG, NULL, &ifstats1->latency_avg);

	REG(PPS_HZ, NULL, &pps_hz);
	REG(OPT_NFLOW, itemlist_callback_nflow, &opt_nflow);
	REG(BUTTON_BPS_L1, itemlist_callback_l1_l2, NULL);
	REG(BUTTON_BPS_L2, itemlist_callback_l1_l2, NULL);
	REG(BPS_DESC, NULL, bps_desc);

	REG(BUTTON_BURST, itemlist_callback_burst_steady, NULL);
	REG(BUTTON_STEADY, itemlist_callback_burst_steady, NULL);
	REG(IF0_PKTSIZE, itemlist_callback_pktsize, &interface[0].pktsize);
	REG(IF1_PKTSIZE, itemlist_callback_pktsize, &interface[1].pktsize);
	REG(IF0_PPS, itemlist_callback_pps, &interface[0].transmit_pps);
	REG(IF1_PPS, itemlist_callback_pps, &interface[1].transmit_pps);
	REG(IF0_PPS_MAX, NULL, &interface[0].transmit_pps_max);
	REG(IF1_PPS_MAX, NULL, &interface[1].transmit_pps_max);
	REG(IF0_IMPLICIT_MBPS, NULL, &interface[0].transmit_Mbps);
	REG(IF1_IMPLICIT_MBPS, NULL, &interface[1].transmit_Mbps);

	REG(IF0_START, itemlist_callback_startstop, NULL);
	REG(IF0_STOP, itemlist_callback_startstop, NULL);
	REG(IF1_START, itemlist_callback_startstop, NULL);
	REG(IF1_STOP, itemlist_callback_startstop, NULL);

	REG(MSGBUF, NULL, msgbuf);

#undef REG

	/* default */
	if (opt_ipg)
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_STEADY, "*");
	else
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BURST, "*");

	if (opt_bps_include_preamble) {
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BPS_L1, "*");
		snprintf(bps_desc, sizeof(bps_desc), "(include PRE+FCS+IFG)");
	} else {
		itemlist_setvalue(itemlist, ITEMLIST_ID_BUTTON_BPS_L2, "*");
		snprintf(bps_desc, sizeof(bps_desc), "(include FCS)");
	}

#ifdef IPG_HACK
	if (support_ipg == 0) {
#else
	if (1) {
#endif
		itemlist_editable(itemlist, ITEMLIST_ID_BUTTON_BURST, 0);
		itemlist_editable(itemlist, ITEMLIST_ID_BUTTON_STEADY, 0);
	}


	if (interface[0].transmit_enable)
		itemlist_setvalue(itemlist, ITEMLIST_ID_IF0_START, "*");
	else
		itemlist_setvalue(itemlist, ITEMLIST_ID_IF0_STOP, "*");

	if (interface[1].transmit_enable)
		itemlist_setvalue(itemlist, ITEMLIST_ID_IF1_START, "*");
	else
		itemlist_setvalue(itemlist, ITEMLIST_ID_IF1_STOP, "*");

	itemlist_focus(itemlist, ITEMLIST_ID_IF1_STOP);

	itemlist_update(itemlist, 1);
}


static void
evt_accept_callback(evutil_socket_t fd, short event __unused, void *arg __unused)
{
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	int client;

	client = accept(fd, (struct sockaddr *)&sin, (socklen_t *)&sinlen);
	if (client < 0) {
		warn("accept");
		return;
	}

	webserv_new(client);
}

static void
evt_readable_stdin_callback(evutil_socket_t fd, short event __unused, void *arg)
{
	struct itemlist *itemlist;

	itemlist = (struct itemlist *)arg;
	control_tty_handler(fd, itemlist);	/* fd = STDIN */
}

static void
evt_timeout_callback(evutil_socket_t fd __unused, short event __unused, void *arg)
{
	struct itemlist *itemlist;

	if (do_quit) {
		quit(false);
		return;
	}

	itemlist = (struct itemlist *)arg;
	control_interval(itemlist);
}


static void *
control_thread_main(void *arg __unused)
{
	struct event ev_tty;
	struct event ev_timer;
	struct event ev_sock;
	struct timeval tv = { 0, 1000000 / DISPLAY_UPDATE_HZ};
	int s;

	if (use_curses) {
		itemlist_init_term();
		itemlist = itemlist_new(pktgen_template, pktgen_items, ITEMLIST_ID_NITEMS);
		control_init_items(itemlist);
	}

	webserv_init();

	/* for libevent */
	s = listentcp(INADDR_ANY, 8080);
	event_init();

	if (use_curses) {
		event_set(&ev_tty, STDIN_FILENO, EV_READ | EV_PERSIST, evt_readable_stdin_callback, itemlist);
		event_add(&ev_tty, NULL);
	}
	event_set(&ev_timer, -1, EV_PERSIST, evt_timeout_callback, itemlist);
	event_add(&ev_timer, &tv);
	event_set(&ev_sock, s, EV_READ | EV_PERSIST, evt_accept_callback, &ev_sock);
	event_add(&ev_sock, NULL);

	event_dispatch();

	return NULL;
}

static void
gentest_main(void)
{
	time_t lastsec = 0;
	uint32_t nsec;
	uint64_t npkt, lpkt;
	static char tmppktbuf[LIBPKT_PKTBUFSIZE] __attribute__((__aligned__(8)));

	clock_gettime(CLOCK_MONOTONIC, &currenttime_main);
	lastsec = currenttime_main.tv_sec;

	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &currenttime_main);
		if (lastsec != currenttime_main.tv_sec) {
			lastsec = currenttime_main.tv_sec;
			break;
		}
	}
	nsec = 0;
	npkt = lpkt = 0;

	printf("Packet generation benchmark. pktsize=%d",
	    interface[0].pktsize);
	if (opt_gentest >= 2)
		printf(" with MEMCPY");
	if (opt_gentest >= 3)
		printf(" with CKSUM test");
	printf(" start\n");

	ip4pkt_udp_template(pktbuffer_ipv4[PKTBUF_UDP][0], 1500 + ETHHDRSIZE);
	build_template_packet_ipv4(0, pktbuffer_ipv4[PKTBUF_UDP][0]);

	clock_gettime(CLOCK_MONOTONIC, &starttime_tx);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &currenttime_main);

		if (opt_time) {
			struct timespec delta;
			timespecsub(&currenttime_main, &starttime_tx, &delta);
			if (delta.tv_sec >= opt_time)
				break;
		}

		touchup_tx_packet(pktbuffer_ipv4[PKTBUF_UDP][0], 0);

		if (opt_gentest >= 2)
			memcpy(tmppktbuf, pktbuffer_ipv4[PKTBUF_UDP][0], interface[0].pktsize + ETHHDRSIZE);
		if (opt_gentest >= 3)
			ip4pkt_test_cksum(tmppktbuf, sizeof(struct ether_header), interface[0].pktsize + ETHHDRSIZE);

		npkt++;
		if (lastsec != currenttime_main.tv_sec) {
			lastsec = currenttime_main.tv_sec;
			nsec++;

			printf("%"PRIu64" pkt generated.", npkt - lpkt);

			printf(" totally %"PRIu64" packet generated in %lu second. average: %"PRIu64" pps, pktsize %d, %.2fMbps\n",
			    npkt,
			    (unsigned long)nsec,
			    npkt / nsec,
			    interface[0].pktsize,
			    calc_mbps(interface[0].pktsize, npkt / nsec));
			fflush(stdout);

			lpkt = npkt;
		}
	}
}

static struct option longopts[] = {
	{	"ipg",				no_argument,		0,	0	},
	{	"burst",			no_argument,		0,	0	},
	{	"l1-bps",			no_argument,		0,	0,	},
	{	"l2-bps",			no_argument,		0,	0,	},
	{	"allnet",			no_argument,		0,	0	},
	{	"fragment",			no_argument,		0,	0	},
	{	"tcp",				no_argument,		0,	0	},
	{	"udp",				no_argument,		0,	0	},
	{	"sport",			required_argument,	0,	0	},
	{	"dport",			required_argument,	0,	0	},
	{	"saddr",			required_argument,	0,	0	},
	{	"daddr",			required_argument,	0,	0	},
	{	"flowlist",			required_argument,	0,	0	},
	{	"flowsort",			no_argument,		0,	0	},
	{	"flowdump",			no_argument,		0,	0	},
	{	"rfc2544",			no_argument,		0,	0	},
	{	"rfc2544-tolerable-error-rate",	required_argument,	0,	0	},
	{	"rfc2544-slowstart",		no_argument,		0,	0	},
	{	"rfc2544-pps-resolution",	required_argument,	0,	0	},
	{	"rfc2544-trial-duration",	required_argument,	0,	0	},
	{	"rfc2544-pktsize",		required_argument,	0,	0	},
	{	"rfc2544-interval",		required_argument,	0,	0	},
	{	"rfc2544-warming-duration",		required_argument,	0,	0	},
	{	"rfc2544-output-json",		required_argument,	0,	0	},
	{	"rfc2544-no-early-finish",		no_argument,		0,	0	},
	{	"nocurses",			no_argument,		0,	0	},
	{	"fail-if-dropped",		no_argument,		0,	0	},
	{	NULL,				0,			NULL,	0	}
};

static void
parse_address(const int ifno, char *s)
{
	struct interface *iface = &interface[ifno];
	char *p;

	p = strsep(&s, "/");
	/* parse IPv4 or IPv6 */
	if (inet_pton(AF_INET, p, &iface->ipaddr) == 1) {
		iface->af_addr = AF_INET;
	} else if (inet_pton(AF_INET6, p, &iface->ip6addr) == 1) {
		iface->af_addr = AF_INET6;
		use_ipv6 = 1;
		update_min_pktsize();
	} else {
		fprintf(stderr, "Cannot resolve: %s\n", p);
		usage();
	}

	if (s == NULL) {
		memset(&iface->ipaddr_mask, 0xff, sizeof(iface->ipaddr_mask));
		memset(&iface->ip6addr_mask, 0xff, sizeof(iface->ip6addr_mask));
	} else {
		if (strchr(s, '.')) {
			if (use_ipv6) {
				fprintf(stderr, "funny address and mask: %s/%s\n", p, s);
				usage();
			}
			inet_pton(AF_INET, s, &iface->ipaddr_mask);
		} else if (strchr(s, ':')) {
			if (!use_ipv6) {
				fprintf(stderr, "funny address and mask: %s/%s\n", p, s);
				usage();
			}
			inet_pton(AF_INET6, s, &iface->ip6addr_mask);
		} else {
			int masklen;

			masklen = strtol(s, NULL, 10);
			switch (iface->af_addr) {
			case AF_INET:
				if (masklen > 32) {
					fprintf(stderr, "illegal address mask: %s\n", s);
					usage();
				}
				iface->ipaddr_mask.s_addr = htonl(0xffffffff << (32 - masklen));
				break;
			case AF_INET6:
				if (masklen > 128) {
					fprintf(stderr, "illegal address mask: %s\n", s);
					usage();
				}
				prefix2in6addr(masklen, &iface->ip6addr_mask);
				break;
			}
		}
	}
}

static void
generate_addrlists(void)
{
	int rc;
	struct in_addr xaddr;
	struct in6_addr xaddr6, xaddr6_begin;

	if (opt_addrrange) {
		if (opt_srcaddr_af == AF_INET) {
			/* exclude hostzero address and gw address and broadcast address */
			xaddr.s_addr = interface[1].ipaddr.s_addr | ~interface[1].ipaddr_mask.s_addr;	/* broadcast */
			addresslist_exclude_daddr(interface[0].adrlist, xaddr);
			addresslist_exclude_saddr(interface[1].adrlist, xaddr);
			xaddr.s_addr = interface[1].ipaddr.s_addr & interface[1].ipaddr_mask.s_addr;	/* hostzero */
			addresslist_exclude_daddr(interface[0].adrlist, xaddr);
			addresslist_exclude_saddr(interface[1].adrlist, xaddr);
			xaddr.s_addr = interface[1].gwaddr.s_addr;					/* gw address */
			addresslist_exclude_daddr(interface[0].adrlist, xaddr);
			addresslist_exclude_saddr(interface[1].adrlist, xaddr);

			xaddr.s_addr = interface[0].ipaddr.s_addr | ~interface[0].ipaddr_mask.s_addr;	/* broadcast */
			addresslist_exclude_saddr(interface[0].adrlist, xaddr);
			addresslist_exclude_daddr(interface[1].adrlist, xaddr);
			xaddr.s_addr = interface[0].ipaddr.s_addr & interface[0].ipaddr_mask.s_addr;	/* hostzero */
			addresslist_exclude_saddr(interface[0].adrlist, xaddr);
			addresslist_exclude_daddr(interface[1].adrlist, xaddr);
			xaddr.s_addr = interface[0].gwaddr.s_addr;					/* gw address */
			addresslist_exclude_saddr(interface[0].adrlist, xaddr);
			addresslist_exclude_daddr(interface[1].adrlist, xaddr);

			if (opt_saddr == 0)
				opt_srcaddr_begin.s_addr = opt_srcaddr_end.s_addr = interface[1].ipaddr.s_addr;
			if (opt_daddr == 0)
				opt_dstaddr_begin.s_addr = opt_dstaddr_end.s_addr = interface[0].ipaddr.s_addr;

			rc = addresslist_append(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    opt_srcaddr_begin, opt_srcaddr_end,
			    opt_dstaddr_begin, opt_dstaddr_end,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			rc = addresslist_append(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    opt_dstaddr_begin, opt_dstaddr_end,
			    opt_srcaddr_begin, opt_srcaddr_end,
			    opt_dstport_begin, opt_dstport_end,
			    opt_srcport_begin, opt_srcport_end);
			if (rc != 0)
				exit(1);
		} else {
			/* exclude gw address */
			xaddr6 = interface[1].gw6addr;						/* gw address */
			addresslist_exclude_daddr6(interface[0].adrlist, &xaddr6);
			addresslist_exclude_saddr6(interface[1].adrlist, &xaddr6);

			xaddr6 = interface[0].gw6addr;						/* gw address */
			addresslist_exclude_saddr6(interface[0].adrlist, &xaddr6);
			addresslist_exclude_daddr6(interface[1].adrlist, &xaddr6);

			if (opt_saddr == 0)
				opt_srcaddr6_begin = opt_srcaddr6_end = interface[1].ip6addr;
			if (opt_daddr == 0)
				opt_dstaddr6_begin = opt_dstaddr6_end = interface[0].ip6addr;

			rc = addresslist_append6(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    &opt_srcaddr6_begin, &opt_srcaddr6_end,
			    &opt_dstaddr6_begin, &opt_dstaddr6_end,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			rc = addresslist_append6(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    &opt_dstaddr6_begin, &opt_dstaddr6_end,
			    &opt_srcaddr6_begin, &opt_srcaddr6_end,
			    opt_dstport_begin, opt_dstport_end,
			    opt_srcport_begin, opt_srcport_end);
			if (rc != 0)
				exit(1);
		}

	} else if (opt_allnet) {

		if (!ipv4_iszero(&interface[0].ipaddr) && !ipv4_iszero(&interface[1].ipaddr)) {
			/* exclude hostzero address and gw address and broadcast address */
			xaddr.s_addr = interface[0].ipaddr.s_addr | ~interface[0].ipaddr_mask.s_addr;	/* broadcast */
			addresslist_exclude_daddr(interface[1].adrlist, xaddr);
			xaddr.s_addr = interface[0].ipaddr.s_addr & interface[0].ipaddr_mask.s_addr;	/* hostzero */
			addresslist_exclude_daddr(interface[1].adrlist, xaddr);
			xaddr.s_addr = interface[0].gwaddr.s_addr;					/* gw address */
			addresslist_exclude_daddr(interface[1].adrlist, xaddr);

			xaddr.s_addr = interface[1].ipaddr.s_addr | ~interface[1].ipaddr_mask.s_addr;	/* broadcast */
			addresslist_exclude_daddr(interface[0].adrlist, xaddr);
			xaddr.s_addr = interface[1].ipaddr.s_addr & interface[1].ipaddr_mask.s_addr;	/* hostzero */
			addresslist_exclude_daddr(interface[0].adrlist, xaddr);
			xaddr.s_addr = interface[1].gwaddr.s_addr;					/* gw address */
			addresslist_exclude_daddr(interface[0].adrlist, xaddr);

			xaddr.s_addr = interface[0].ipaddr.s_addr | ~interface[0].ipaddr_mask.s_addr;	/* broadcast */
			rc = addresslist_append(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    interface[1].ipaddr, interface[1].ipaddr,
			    interface[0].ipaddr, xaddr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			xaddr.s_addr = interface[1].ipaddr.s_addr | ~interface[0].ipaddr_mask.s_addr;	/* broadcast */
			rc = addresslist_append(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    interface[0].ipaddr, interface[0].ipaddr,
			    interface[1].ipaddr, xaddr,
			    opt_dstport_begin, opt_dstport_end,
			    opt_srcport_begin, opt_srcport_end);
			if (rc != 0)
				exit(1);

		} else if (!ipv6_iszero(&interface[0].ip6addr) && !ipv6_iszero(&interface[1].ip6addr)) {
			/* exclude gw address */
			xaddr6 = interface[0].gw6addr;					/* gw address */
			addresslist_exclude_daddr6(interface[1].adrlist, &xaddr6);
			xaddr6 = interface[1].gw6addr;					/* gw address */
			addresslist_exclude_daddr6(interface[0].adrlist, &xaddr6);

			/* e.g.) fd00::1/112 => from fd00:0 to fd00::ffff */
			xaddr6_begin = interface[0].ip6addr_mask;
			ipv6_and(&interface[0].ip6addr, &xaddr6_begin, &xaddr6_begin);	/* beginning of network address */
			ipv6_not(&interface[0].ip6addr_mask, &xaddr6);
			ipv6_or(&interface[0].ip6addr, &xaddr6, &xaddr6);	/* end of network address */
			rc = addresslist_append6(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    &interface[1].ip6addr, &interface[1].ip6addr,
			    &xaddr6_begin, &xaddr6,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			xaddr6_begin = interface[1].ip6addr_mask;
			ipv6_and(&interface[1].ip6addr, &xaddr6_begin, &xaddr6_begin);	/* beginning of network address */
			ipv6_not(&interface[1].ip6addr_mask, &xaddr6);
			ipv6_or(&interface[1].ip6addr, &xaddr6, &xaddr6);	/* last of network address */
			rc = addresslist_append6(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    &interface[0].ip6addr, &interface[0].ip6addr,
			    &xaddr6_begin, &xaddr6,
			    opt_dstport_begin, opt_dstport_end,
			    opt_srcport_begin, opt_srcport_end);
			if (rc != 0)
				exit(1);

		} else {
			fprintf(stderr, "no address info on %s and %s\n",
			    interface[0].ifname, interface[1].ifname);
			exit(1);
		}

	} else {
		if (!ipv4_iszero(&interface[0].ipaddr) && !ipv4_iszero(&interface[1].ipaddr)) {
			rc = addresslist_append(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    interface[1].ipaddr, interface[1].ipaddr,
			    interface[0].ipaddr, interface[0].ipaddr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			rc = addresslist_append(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    interface[0].ipaddr, interface[0].ipaddr,
			    interface[1].ipaddr, interface[1].ipaddr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

		} else if (!ipv6_iszero(&interface[0].ip6addr) && !ipv6_iszero(&interface[1].ip6addr)) {
			rc = addresslist_append6(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    &interface[1].ip6addr, &interface[1].ip6addr,
			    &interface[0].ip6addr, &interface[0].ip6addr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			rc = addresslist_append6(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    &interface[0].ip6addr, &interface[0].ip6addr,
			    &interface[1].ip6addr, &interface[1].ip6addr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);
		} else {
			/* no address information. use 0.0.0.0-0.0.0.0 */
			rc = addresslist_append(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    interface[1].ipaddr, interface[1].ipaddr,
			    interface[0].ipaddr, interface[0].ipaddr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);

			rc = addresslist_append(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP,
			    interface[0].ipaddr, interface[0].ipaddr,
			    interface[1].ipaddr, interface[1].ipaddr,
			    opt_srcport_begin, opt_srcport_end,
			    opt_dstport_begin, opt_dstport_end);
			if (rc != 0)
				exit(1);
		}
	}
}

int
main(int argc, char *argv[])
{
	int ifnum[2] = { 0, 1 };
	unsigned int i, j;
	int ch, optidx;
	int pps;
	int pppoe = 0;
	int vlan = 0;
	char ifname[2][IFNAMSIZ];
	char *testscript = NULL;
	uint64_t maxlinkspeed;

	DEBUGOPEN("ipgen-debug.log");

	/* XXX */
	seq_magic = getpid() & 0xffff;

	memset(ifname, 0, sizeof(ifname));

	/* initialize instances */
	pps = -1;
	for (i = 0; i < 2; i++) {
		interface_init(i);
		pbufq_init(&interface[i].pbufq);
		interface[i].pktsize = min_pktsize;
	}

	while ((ch = getopt_long(argc, argv, "D:dF:fH:L:n:Pp:R:S:s:T:t:vV:X", longopts, &optidx)) != -1) {
		switch (ch) {
		case 'd':
			opt_debuglevel++;
			break;
		case 'D':
			opt_debug = optarg;
			break;

		case 'P':
			pppoe = 1;
			break;
		case 'V':
			vlan = strtol(optarg, (char **)NULL, 10);
			if (vlan < 0 || vlan >= 4096) {
				fprintf(stderr, "illegal vlan id: %s\n", optarg);
				usage();
			}
			break;

		case 'T':
		case 'R': {
			char *p, *s, *tofree;
			int ifno = (ch == 'T') ? 1 : 0;
			struct interface *iface = &interface[ifno];

			tofree = s = strdup(optarg);

			if (vlan && pppoe) {
				fprintf(stderr, "VLAN (-V) and PPPoE (-P) cannot be specified at the same time\n");
				usage();
			}
#ifndef SUPPORT_PPPOE
			if (pppoe) {
				fprintf(stderr, "PPPoE is not supported on this OS\n");
				usage();
			}
#endif
			iface->vlan_id = vlan;
			iface->pppoe = pppoe;
			vlan = 0;
			pppoe = 0;

			/*
			 * parse
			 *    "-Tem0,10.0.0.1"
			 *    "-Tem0,fd00::1"
			 *    "-Tem0,aa:bb:cc:dd:ee:ff"
			 * or "-Tem0,10.0.0.1,10.0.0.2"
			 * or "-Tem0,fd00:1,fd00::2"
			 * or "-Tem0,aa:bb:cc:dd:ee:ff,10.0.0.2"
			 * or "-Tem0,aa:bb:cc:dd:ee:ff,fd00::2"
			 * or "-Tem0,10.0.0.1,10.0.0.2/24"
			 * or "-Tem0,fd00::1,fd00::2/64"
			 * or "-Tem0,aa:bb:cc:dd:ee:ff,10.0.0.2/24"
			 * or "-Tem0,aa:bb:cc:dd:ee:ff,fd00::2/64"
			 */
			p = strsep(&s, ",");
			if (s == NULL)
				usage();
			strncpy(ifname[ifno], p, sizeof(ifname[0]));

			setup_ipg(ifno, ifname[ifno]);

			p = strsep(&s, ",");
			/* parse IPv4 or IPv6 or MAC-ADDRESS */
			if (inet_pton(AF_INET, p, &iface->gwaddr) == 1) {
				iface->af_gwaddr = AF_INET;
			} else if (inet_pton(AF_INET6, p, &iface->gw6addr) == 1) {
				iface->af_gwaddr = AF_INET6;
			} else if (ether_aton_r(p, &iface->gweaddr) != NULL) {
				/* gweaddr is ok */
			} else if (strcmp(p, "random") == 0) {
				iface->gw_l2random = 1;
			} else {
				fprintf(stderr, "Cannot resolve: %s\n", p);
				usage();
			}

			if (s != NULL)
				parse_address(ifno, s);

			free(tofree);

#ifdef SUPPORT_PPPOE
			if (pppoe) {
				if (iface->af_gwaddr != AF_INET ||
				    iface->af_addr != AF_INET) {
					fprintf(stderr, "For PPPoE, gateway-address and down-address must be IP addresses: %s\n", optarg);
					usage();
				}
			}
#endif
			break;
		    }
		case 'X':
			opt_gentest++;
			break;
		case 'f':
			opt_fulldup++;
			break;
		case 'F':
			opt_nflow = strtol(optarg, (char **)NULL, 10);
			break;

		case 'L':
			logfd = open(optarg, O_WRONLY|O_CREAT|O_TRUNC, 0666);
			if (logfd < 0) {
				err(2, "%s", optarg);
			}
			break;

		case 'n':
			opt_npkt_sync = strtol(optarg, (char **)NULL, 10);
			break;

		case 'H':
			pps_hz = strtol(optarg, (char **)NULL, 10);
			if (pps_hz < 1) {
				fprintf(stderr, "HZ must be greater than 1\n");
				exit(1);
			}
			break;

		case 'p':
			pps = strtol(optarg, (char **)NULL, 10);
			break;
		case 'S':
			testscript = optarg;
			break;
		case 's':
			{
				int sz;
				sz = strtol(optarg, (char **)NULL, 10);
				if (sz < 46 || sz > 1500) {
					usage();
				}
				interface[0].pktsize = sz;
				interface[1].pktsize = sz;
			}
			break;
		case 't':
			{
				int time;
				time = strtol(optarg, (char **)NULL, 10);
				if (time < 0) {
					usage();
				}
				opt_time = time;
			}
			break;
		case 'v':
			verbose++;
			break;
		case 0:
			if (strcmp(longopts[optidx].name, "ipg") == 0) {
				opt_ipg = 1;
			} else if (strcmp(longopts[optidx].name, "burst") == 0) {
				opt_ipg = 0;
			} else if (strcmp(longopts[optidx].name, "l1-bps") == 0) {
				opt_bps_include_preamble = 1;
			} else if (strcmp(longopts[optidx].name, "l2-bps") == 0) {
				opt_bps_include_preamble = 0;
			} else if (strcmp(longopts[optidx].name, "allnet") == 0) {
				opt_allnet = 1;
			} else if (strcmp(longopts[optidx].name, "fragment") == 0) {
				opt_fragment = 1;
			} else if (strcmp(longopts[optidx].name, "tcp") == 0) {
				opt_tcp = 1;
				opt_udp = 0;
				min_pktsize = MAX(min_pktsize, sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct seqdata));
			} else if (strcmp(longopts[optidx].name, "udp") == 0) {
				opt_udp = 1;
				opt_tcp = 0;
				min_pktsize = MAX(min_pktsize, sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct seqdata));
			} else if (strcmp(longopts[optidx].name, "sport") == 0) {
				parse_portrange(optarg, &opt_srcport_begin, &opt_srcport_end);
			} else if (strcmp(longopts[optidx].name, "dport") == 0) {
				parse_portrange(optarg, &opt_dstport_begin, &opt_dstport_end);
			} else if (strcmp(longopts[optidx].name, "saddr") == 0) {
				opt_addrrange = 1;
				opt_saddr = 1;
				if (parse_addrrange(optarg, &opt_srcaddr_begin, &opt_srcaddr_end) == 0) {
					opt_srcaddr_af = AF_INET;
				} else if (parse_addr6range(optarg, &opt_srcaddr6_begin, &opt_srcaddr6_end) == 0) {
					opt_srcaddr_af = AF_INET6;
				} else {
					fprintf(stderr, "illegal address range: %s\n", optarg);
					exit(1);
				}
			} else if (strcmp(longopts[optidx].name, "daddr") == 0) {
				opt_addrrange = 1;
				opt_daddr = 1;
				if (parse_addrrange(optarg, &opt_dstaddr_begin, &opt_dstaddr_end) == 0) {
					opt_dstaddr_af = AF_INET;
				} else if (parse_addr6range(optarg, &opt_dstaddr6_begin, &opt_dstaddr6_end) == 0) {
					opt_dstaddr_af = AF_INET6;
				} else {
					fprintf(stderr, "illegal address range: %s\n", optarg);
					exit(1);
				}
			} else if (strcmp(longopts[optidx].name, "flowsort") == 0) {
				opt_flowsort = 1;
			} else if (strcmp(longopts[optidx].name, "flowdump") == 0) {
				opt_flowdump = 1;
			} else if (strcmp(longopts[optidx].name, "flowlist") == 0) {
				opt_flowlist = optarg;
			} else if (strcmp(longopts[optidx].name, "rfc2544") == 0) {
				opt_rfc2544 = 1;
			} else if (strcmp(longopts[optidx].name, "rfc2544-tolerable-error-rate") == 0) {
				opt_rfc2544_tolerable_error_rate = strtod(optarg, (char **)NULL);
				if ((opt_rfc2544_tolerable_error_rate > 100.0) ||
				    (opt_rfc2544_tolerable_error_rate < 0.0)) {
					fprintf(stderr, "illegal error rate. must be 0.0-100.0: %s\n", optarg);
					exit(1);
				}
			} else if (strcmp(longopts[optidx].name, "rfc2544-slowstart") == 0) {
				opt_rfc2544_slowstart = 1;
			} else if (strcmp(longopts[optidx].name, "rfc2544-pps-resolution") == 0) {
				opt_rfc2544_ppsresolution = strtod(optarg, (char **)NULL);
				if ((opt_rfc2544_ppsresolution > 100.0) ||
				    (opt_rfc2544_ppsresolution < 0.0)) {
					fprintf(stderr, "illegal pps resolution rate. must be 0.0-100.0: %s\n", optarg);
					exit(1);
				}
			} else if (strcmp(longopts[optidx].name, "rfc2544-trial-duration") == 0) {
				opt_rfc2544_trial_duration = strtol(optarg, (char **)NULL, 10);
				if (opt_rfc2544_trial_duration < 3)
					opt_rfc2544_trial_duration = 3;
			} else if (strcmp(longopts[optidx].name, "rfc2544-pktsize") == 0) {
				opt_rfc2544_pktsize = optarg;
			} else if (strcmp(longopts[optidx].name, "rfc2544-output-json") == 0) {
				opt_rfc2544_output_json = optarg;
			} else if (strcmp(longopts[optidx].name, "rfc2544-interval") == 0) {
				opt_rfc2544_interval = strtol(optarg, (char **)NULL, 10);
				if (opt_rfc2544_interval < 0 || opt_rfc2544_interval > 60) {
					fprintf(stderr, "illegal interval. must be 0-60: %s\n", optarg);
					exit(1);
				}
			} else if (strcmp(longopts[optidx].name, "rfc2544-warming-duration") == 0) {
				opt_rfc2544_warming_duration = strtol(optarg, (char **)NULL, 10);
				if (opt_rfc2544_warming_duration < 1 || opt_rfc2544_warming_duration > 60) {
					fprintf(stderr, "illegal interval. must be 1-60: %s\n", optarg);
					exit(1);
				}
			} else if (strcmp(longopts[optidx].name, "rfc2544-no-early-finish") == 0) {
				opt_rfc2544_early_finish = 0;
			} else if (strcmp(longopts[optidx].name, "nocurses") == 0) {
				use_curses = false;
			} else if (strcmp(longopts[optidx].name, "fail-if-dropped") == 0) {
				opt_fail_if_dropped = 1;
			} else {
				usage();
			}
			break;
		default:
			usage();
		}
	}

	printf_verbose("ipgen v%s\n", ipgen_version);
	printf_verbose("\n");

	if (opt_time && (opt_rfc2544 || testscript != NULL)) {
		fprintf(stderr, "cannot use -t with --rfc2544 or -S at the same time\n");
		exit(1);
	}

	if (opt_addrrange && opt_allnet) {
		fprintf(stderr, "cannot use --allnet and --saddr/--daddr at the same time\n");
		exit(1);
	}

	if (opt_srcaddr_af == 0)
		opt_srcaddr_af = opt_dstaddr_af;
	if (opt_dstaddr_af == 0)
		opt_dstaddr_af = opt_srcaddr_af;
	if (opt_addrrange && (opt_srcaddr_af != opt_dstaddr_af)) {
		fprintf(stderr, "--saddr and --daddr are different address family\n");
		exit(1);
	}

	if ((interface[0].pktsize < min_pktsize) && opt_tcp) {
		fprintf(stderr, "minimal pakcet size is %d when using TCP\n", min_pktsize);
		exit(1);
	}

	if (!in_range(opt_srcport_begin, 0, 65535) ||
	    !in_range(opt_srcport_end, 0, 65535) ||
	    !in_range(opt_dstport_begin, 0, 65535) ||
	    !in_range(opt_dstport_end, 0, 65535)) {
		fprintf(stderr, "illegal port %d-%d, %d-%d\n",
		    opt_srcport_begin, opt_srcport_end,
		    opt_dstport_begin, opt_dstport_end);
		usage();
	}
	if ((opt_srcport_begin > opt_srcport_end) ||
	    (opt_dstport_begin > opt_dstport_end)) {
		fprintf(stderr, "illegal port order\n");
		usage();
	}

	if (opt_debug != NULL) {
		debug_tcpdump_fd = tcpdumpfile_open(opt_debug);
		if (debug_tcpdump_fd < 0) {
			fprintf(stderr, "%s: %s\n", opt_debug, strerror(debug_tcpdump_fd));
			exit(1);
		}
	}

	if (opt_gentest) {
		gentest_main();
		exit(0);
	}

	if (ifname[0][0] == '\0')
		opt_txonly = 1;
	if (ifname[1][0] == '\0')
		opt_rxonly = 1;

	if (opt_txonly && opt_rxonly) {
		fprintf(stderr, "specify interface with -T and -R\n");
		usage();
	}

	if (!opt_txonly)
		interface_up(ifname[0]);	/* RX */
	if (!opt_rxonly)
		interface_up(ifname[1]);	/* TX */

	if (!opt_rxonly)
		interface_wait_linkup(ifname[1]);	/* TX */
	if (!opt_txonly)
		interface_wait_linkup(ifname[0]);	/* RX */

	for (i = 0; i < 2; i++) {
		if (opt_txonly && i == 0)
			continue;
		if (opt_rxonly && i == 1)
			continue;

		/* Set maxlinkspeed */
		for (j = 0; j < sizeof(ifflags)/sizeof(ifflags[0]); j++) {
			uint64_t linkspeed;
			int trials = 5;
			while (--trials > 0) {
				linkspeed = interface_get_baudrate(ifname[i]);
				if (linkspeed > 0)
					break;
				sleep(1);
			}
			if (linkspeed == 0) {
				fprintf(stderr, "%s: failed to determine linkspeed\n", ifname[i]);
				exit(1);
			}

			if (linkspeed > 0) {
				if (linkspeed < IF_Mbps(10)) {
					/*
					 * If the baudrate is lower than 10Mbps,
					 * something is wrong.
					 */
					fprintf(stderr,
					    "%s: WARINIG: baudrate(%lu) < IF_Mbps(10)\n",
					    ifname[i], linkspeed);
				} else {
					interface[i].maxlinkspeed = linkspeed;
					printf_verbose("%s: linkspeed = %lu\n", ifname[i], linkspeed);
					break;
				}
			}

			/*
			 * If we failed to get the link speed from sysctl,
			 * get the default link speed from ifflags[] table.
			 */
			if (strncmp(ifname[i], ifflags[j].drvname,
			    strnlen(ifflags[j].drvname, IFNAMSIZ)) == 0) {
				interface[i].maxlinkspeed = ifflags[j].maxlinkspeed;
				break;
			}
		}
		if (interface[i].maxlinkspeed == 0)
			interface[i].maxlinkspeed = LINKSPEED_1GBPS; /* XXX 10 Gbps */

		if ((interface[i].af_gwaddr != 0) &&
		    (memcmp(eth_zero, &interface[i].gweaddr, ETHER_ADDR_LEN) == 0) &&
		    ipv4_iszero(&interface[i].gwaddr) &&
		    ipv6_iszero(&interface[i].gw6addr)) {
			fprintf(stderr, "gateway address is unknown. specify gw address with -T and -R\n");
			usage();
		}
	}

	if (pps == -1) {
		for (i = 0; i < 2; i++)
			if (interface[i].maxlinkspeed == LINKSPEED_1GBPS)
				pps = 1488095;
			else if (interface[i].maxlinkspeed == LINKSPEED_10GBPS)
				pps = 14880952;
			else
				pps = 148809524;
	}

	maxlinkspeed = 0;
	for (i = 0; i < 2; i++) {
		if (maxlinkspeed < interface[i].maxlinkspeed)
			maxlinkspeed = interface[i].maxlinkspeed;
	}

	if (opt_rfc2544_pktsize != NULL) {
		char buf[128];
		int pktsize;
		char *p, *save = NULL;

		while ((p = getword(opt_rfc2544_pktsize, ',', &save, buf, sizeof(buf))) != NULL) {
			pktsize = atoi(buf);
			if ((pktsize < 46) || (pktsize > 1500)) {
				fprintf(stderr, "illegal packet size in --rfc2544_pktsize: %d\n", pktsize);
				exit(1);
			}
			rfc2544_add_test(maxlinkspeed, pktsize);
		}
	}

	if (rfc2544_ntest == 0)
		rfc2544_load_default_test(maxlinkspeed);

	if (opt_rfc2544)
		rfc2544_calc_param(maxlinkspeed);


	if (testscript != NULL) {
		genscript = genscript_new(testscript);
		if (genscript == NULL)
			err(2, "%s", testscript);

		setpps(0, 0);
		setpps(1, 0);
	} else {
		setpps(0, pps);
		setpps(1, pps);
	}

	/* check console size */
	if (use_curses) {
		struct winsize winsize;
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize) != 0) {
			fprintf(stderr, "cannot get terminal size\n");
			exit(3);
		}
		if ((winsize.ws_row < pktgen_template_line) ||
		    (winsize.ws_col < pktgen_template_column)) {
			fprintf(stderr, "not enough screen size. screen size is %dx%d, requires %dx%d\n",
			    winsize.ws_col, winsize.ws_row,
			    pktgen_template_column, pktgen_template_line);
			exit(3);
		}
	}


	for (i = 0; i < 2; i++) {
		interface[i].transmit_txhz = interface[i].transmit_pps / pps_hz;
	}

	if (!opt_txonly)
		interface_setup(0, ifname[0]);	/* RX */
	if (!opt_rxonly)
		interface_setup(1, ifname[1]);	/* TX */


	/*
	 * configure adrlist
	 */
	for (i = 0; i < 2; i++) {
		interface[i].adrlist = addresslist_new();
		addresslist_setlimit(interface[i].adrlist, MAXFLOWNUM);
	}

	if (opt_flowlist != NULL) {
		FILE *fh;
		char *line;
		char buf[1024];
		size_t len, lineno;
		int anyerror;

		fh = fopen(opt_flowlist, "r");
		if (fh == NULL) {
			fprintf(stderr, "%s: %s\n", opt_flowlist, strerror(errno));
			exit(2);
		}

		anyerror = 0;
		for (lineno = 1; ((line = fgets(buf, sizeof(buf), fh)) != NULL); lineno++) {
			while ((*line == ' ') || (*line == '\t'))
				line++;
			if (line[0] == '#')
				continue;

			/* chop '\n' */
			len = strlen(line);
			if (len > 0)
				line[len - 1] = '\0';

			if (line[0] == '\0')	/* blank */
				continue;

			/* for TX */
			if (parse_flowstr(interface[1].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP, line, false) != 0) {
				fprintf(stderr, "%s:%"PRIu64": cannot parse: \"%s\"\n", opt_flowlist, lineno, line);
				anyerror++;
			}
			/* for RX */
			parse_flowstr(interface[0].adrlist, opt_tcp ? IPPROTO_TCP : IPPROTO_UDP, line, true);
		}
		fclose(fh);
		if (anyerror)
			exit(2);

	} else {
		/* Generate interface[].adrlist based on specified addresses and options */
		generate_addrlists();
	}

	if (addresslist_include_af(interface[0].adrlist, AF_INET6) ||
	    addresslist_include_af(interface[1].adrlist, AF_INET6)) {
		use_ipv6 = 1;
	} else {
		use_ipv6 = 0;
	}
	update_min_pktsize();

	if (opt_flowsort) {
		addresslist_rebuild(interface[1].adrlist);
		addresslist_rebuild(interface[0].adrlist);
	}
	if (opt_flowdump) {
		printf("\nflowlist of TX side interface\n");
		addresslist_dump(interface[1].adrlist);
		printf("\nflowlist of RX side interface\n");
		addresslist_dump(interface[0].adrlist);
		exit(1);
	}

	if (addresslist_get_tuplenum(interface[1].adrlist) == 0) {
		fprintf(stderr, "--saddr: no valid addresses. (hostzero, gateway or broadcast address were excluded)\n");
		exit(1);
	}
	if (addresslist_get_tuplenum(interface[0].adrlist) == 0) {
		fprintf(stderr, "--daddr: no valid addresses. (hostzero, gateway or broadcast address were excluded)\n");
		exit(1);
	}


	printf_verbose("HZ=%d\n", pps_hz);
	printf_verbose("%s %s %s, ",
	    ifname[1],
	    opt_fulldup ? "<->" : "->",
	    ifname[0]);

	printf_verbose("opt_bps_include_preamble=%d\n", opt_bps_include_preamble);

	if (!opt_rfc2544) {
		printf("IP pktsize %d, %u pps, %.1f Mbps (%lu bps)\n", interface[0].pktsize, interface[0].transmit_pps,
		    calc_mbps(interface[0].pktsize, interface[0].transmit_pps),
		    (unsigned long)calc_bps(interface[0].pktsize, interface[0].transmit_pps));
	}

	/*
	 * open netmap devices
	 */
	if (!opt_txonly)
		interface_open(0);	/* RX */
	if (!opt_rxonly)
		interface_open(1);	/* TX */

	if (!opt_rxonly)
		interface_wait_linkup(ifname[1]);	/* TX */
	if (!opt_txonly)
		interface_wait_linkup(ifname[0]);	/* RX */

	for (i = 0; i < 2; i++) {
		char inetbuf1[INET6_ADDRSTRLEN];
		char inetbuf2[INET6_ADDRSTRLEN];

		if (verbose == 0)
			break;

		printf("%s(%s)",
		    interface[i].ifname,
		    ether_ntoa(&interface[i].eaddr));

		switch (interface[i].af_addr) {
		case AF_INET:
			printf(" %s/%s",
			    inet_ntop(AF_INET, &interface[i].ipaddr, inetbuf1, sizeof(inetbuf1)),
			    inet_ntop(AF_INET, &interface[i].ipaddr_mask, inetbuf2, sizeof(inetbuf2)));
			break;
		case AF_INET6:
			printf(" %s/%d",
			    inet_ntop(AF_INET6, &interface[i].ip6addr, inetbuf1, sizeof(inetbuf1)),
			    in6addr2prefix(&interface[i].ip6addr_mask));
			break;
		}

		switch (interface[i].af_gwaddr) {
		case AF_INET:
			printf(" -> %s(%s)\n",
			    ether_ntoa(&interface[i].gweaddr),
			    inet_ntop(AF_INET, &interface[i].gwaddr, inetbuf1, sizeof(inetbuf1)));
			break;
		case AF_INET6:
			printf(" -> %s(%s)\n",
			    ether_ntoa(&interface[i].gweaddr),
			    inet_ntop(AF_INET6, &interface[i].gw6addr, inetbuf1, sizeof(inetbuf1)));
			break;
		default:
			printf(" -> %s\n",
			    ether_ntoa(&interface[i].gweaddr));
			break;
		}
	}

	if (opt_nflow == 0)
		opt_nflow = MAX(get_flownum(0), get_flownum(1));

	/*
	 * allocate per frame seqchecker
	 */
	j = get_flownum(0);
	interface[0].sequence_tx_perflow = malloc(sizeof(uint64_t) * j);
	memset(interface[0].sequence_tx_perflow, 0, sizeof(uint64_t) * j);
	interface[0].seqchecker_perflow = malloc(sizeof(struct sequencechecker *) * j);
	interface[0].seqchecker_flowtotal = seqcheck_new();
	for (i = 0; i < j; i++) {
		interface[0].seqchecker_perflow[i] = seqcheck_new();
		if (interface[0].seqchecker_perflow[i] == NULL) {
			fprintf(stderr, "cannot allocate %s flow sequence work %d/%d\n", interface[0].ifname, i, j);
			exit(1);
		}
		seqcheck_setparent(interface[0].seqchecker_perflow[i], interface[0].seqchecker_flowtotal);
	}

	j = get_flownum(1);
	interface[1].sequence_tx_perflow = malloc(sizeof(uint64_t) * j);
	memset(interface[1].sequence_tx_perflow, 0, sizeof(uint64_t) * j);
	interface[1].seqchecker_perflow = malloc(sizeof(struct sequencechecker *) * j);
	interface[1].seqchecker_flowtotal = seqcheck_new();
	for (i = 0; i < j; i++) {
		interface[1].seqchecker_perflow[i] = seqcheck_new();
		if (interface[1].seqchecker_perflow[i] == NULL) {
			fprintf(stderr, "cannot allocate %s flow sequence work %d/%d\n", interface[1].ifname, i, j);
			exit(1);
		}
		seqcheck_setparent(interface[1].seqchecker_perflow[i], interface[1].seqchecker_flowtotal);
	}


	for (i = 0; i < 2; i++) {
		ip4pkt_udp_template(pktbuffer_ipv4[PKTBUF_UDP][i], 1500 + ETHHDRSIZE);
		build_template_packet_ipv4(i, pktbuffer_ipv4[PKTBUF_UDP][i]);
		ip4pkt_tcp_template(pktbuffer_ipv4[PKTBUF_TCP][i], 1500 + ETHHDRSIZE);
		build_template_packet_ipv4(i, pktbuffer_ipv4[PKTBUF_TCP][i]);
		ip6pkt_udp_template(pktbuffer_ipv6[PKTBUF_UDP][i], 1500 + ETHHDRSIZE);
		build_template_packet_ipv6(i, pktbuffer_ipv6[PKTBUF_UDP][i]);
		ip6pkt_tcp_template(pktbuffer_ipv6[PKTBUF_TCP][i], 1500 + ETHHDRSIZE);
		build_template_packet_ipv6(i, pktbuffer_ipv6[PKTBUF_TCP][i]);
	}

	if (!opt_txonly) {
		pthread_create(&txthread0, NULL, tx_thread_main, &ifnum[0]);
		pthread_create(&rxthread0, NULL, rx_thread_main, &ifnum[0]);
		{
			char buf[128];
			snprintf(buf, sizeof(buf), "%s-tx", interface[0].ifname);
			pthread_setname_np(txthread0, buf);
			snprintf(buf, sizeof(buf), "%s-rx", interface[0].ifname);
			pthread_setname_np(rxthread0, buf);
		}
#ifdef __linux__
		int error, i;
		long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		/* Assign even CPU cores to Tx threads, the others to Rx thread */
		for (i = 0; i < nprocs; i += 2)
			CPU_SET(i, &cpuset);
		error = pthread_setaffinity_np(txthread0, sizeof(cpuset), &cpuset);
		error = pthread_setaffinity_np(rxthread0, sizeof(cpuset), &cpuset);
#if 0
		struct sched_param param;
		param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		error = pthread_setschedparam(txthread0, SCHED_FIFO, &param);
		error = pthread_setschedparam(rxthread0, SCHED_FIFO, &param);
#endif
#endif
	}
	if (!opt_rxonly) {
		pthread_create(&txthread1, NULL, tx_thread_main, &ifnum[1]);
		pthread_create(&rxthread1, NULL, rx_thread_main, &ifnum[1]);
		{
			char buf[128];
			snprintf(buf, sizeof(buf), "%s-tx", interface[1].ifname);
			pthread_setname_np(txthread1, buf);
			snprintf(buf, sizeof(buf), "%s-rx", interface[1].ifname);
			pthread_setname_np(rxthread1, buf);
		}
#ifdef __linux__
		int error, i;
		long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		if (nprocs == 1) {
			fprintf(stderr, "warning: Tx and Rx threads share a CPU");
			CPU_SET(0, &cpuset);
		} else {
			for (i = 1; i < nprocs; i += 2)
				CPU_SET(i, &cpuset);
		}
		error = pthread_setaffinity_np(txthread1, sizeof(cpuset), &cpuset);
		error = pthread_setaffinity_np(rxthread1, sizeof(cpuset), &cpuset);
#if 0
		struct sched_param param;
		param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		error = pthread_setschedparam(txthread1, SCHED_FIFO, &param);
		error = pthread_setschedparam(rxthread1, SCHED_FIFO, &param);
#endif
#endif
	}

	/* update transmit flags */
	if (!opt_txonly && opt_fulldup)
		transmit_set(0, 1);
	if (!opt_rxonly)
		transmit_set(1, 1);


	clock_gettime(CLOCK_MONOTONIC, &currenttime_main);

	/*
	 * setup signals
	 */
	(void)sigemptyset(&used_sigset);

	(void)sigaddset(&used_sigset, SIGHUP);
	(void)sigaddset(&used_sigset, SIGINT);
	(void)sigaddset(&used_sigset, SIGQUIT);
	signal(SIGHUP, sighandler_int);
	signal(SIGINT, sighandler_int);
	signal(SIGQUIT, sighandler_int);

	if (use_curses) {
		(void)sigaddset(&used_sigset, SIGTSTP);
		(void)sigaddset(&used_sigset, SIGCONT);
		signal(SIGTSTP, sighandler_tstp);
		signal(SIGCONT, sighandler_cont);
	}

	(void)sigaddset(&used_sigset, SIGALRM);
	signal(SIGALRM, sighandler_alrm);
	{
		struct itimerval itv;
		memset(&itv, 0, sizeof(itv));
		itv.it_interval.tv_sec = 0;
		itv.it_interval.tv_usec = 1000000 / pps_hz;
		itv.it_value = itv.it_interval;
		setitimer(ITIMER_REAL, &itv, NULL);
	}

	/* CUI/web interface thread */
	control_thread_main(NULL);

	DEBUGCLOSE();
	return 0;
}
