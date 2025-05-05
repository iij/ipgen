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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_mib.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#endif
#ifdef __linux__
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <bsd/string.h>
#endif
#include "util.h"
#include "compat.h"

char *
ip6_sprintf(struct in6_addr *addr)
{
	static char buf[8][INET6_ADDRSTRLEN];
	static int i;
	char *p = buf[i++ & 7];

	inet_ntop(AF_INET6, addr, p, sizeof(buf[0]));
	return p;
}

char *
ip4_sprintf(struct in_addr *addr)
{
	static char buf[8][INET_ADDRSTRLEN];
	static int i;
	char *p = buf[i++ & 7];

	inet_ntop(AF_INET, addr, p, sizeof(buf[0]));
	return p;
}

void
prefix2in6addr(int prefix, struct in6_addr *addr)
{
	if (prefix > 128)
		prefix = 128;

	if (prefix < 128)
		memset(&addr->s6_addr[prefix / 8], 0, 16 - (prefix / 8));
	if (prefix >= 8)
		memset(addr, 0xff, prefix / 8);
	if (prefix < 128)
		addr->s6_addr[prefix / 8] = 0xff << (8 - (prefix & 7));
}

unsigned int
in6addr2prefix(struct in6_addr *addr)
{
	unsigned int prefix;
	int i;

	for (prefix = 0; prefix < 128; prefix += 8) {
		if (addr->s6_addr[prefix / 8] != 0xff) {
			for (i = 0; i < 8; i++) {
				if ((addr->s6_addr[prefix / 8] & (0x80 >> i)) != 0) {
					prefix += i;
					break;
				}
			}
			break;
		}
	}

	return prefix;
}

int
ipv6_iszero(struct in6_addr *addr)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (addr->s6_addr[i] != 0)
			return 0;
	}
	return 1;
}

int
ipv4_iszero(struct in_addr *addr)
{
	if (addr->s_addr == 0)
		return 1;

	return 0;
}

int
ipv6_not(struct in6_addr *src, struct in6_addr *dst)
{
	int i;

	for (i = 0; i < 16; i++)
		dst->s6_addr[i] = ~src->s6_addr[i];

	return 0;
}

int
ipv6_and(struct in6_addr *a, struct in6_addr *b, struct in6_addr *dst)
{
	int i;

	for (i = 0; i < 16; i++)
		dst->s6_addr[i] = a->s6_addr[i] & b->s6_addr[i];

	return 0;
}

int
ipv6_or(struct in6_addr *a, struct in6_addr *b, struct in6_addr *dst)
{
	int i;

	for (i = 0; i < 16; i++)
		dst->s6_addr[i] = a->s6_addr[i] | b->s6_addr[i];

	return 0;
}

void
chop(char *p)
{
	char c;

	for (c = '\0'; *p != '\0'; c = *p++)
		;
	if (c == '\n')
		*--p = '\0';
}

char *
getword(char *str, char sep, char **save, char *buf, size_t bufsize)
{
	char *s;
	char c, *d;
	size_t len;

	s = str;
	d = buf;
	len = 0;

	if (*save != NULL)
		s = *save;

	if (*s == '\0')
		return NULL;

	for (;;) {
		c = *s++;
		if (c == '\0') {
			*d++ = '\0';
			*save = --s;
			break;
		}
		if (c == sep) {
			*d++ = '\0';
			*save = s;
			break;
		}

		if (++len < bufsize)
			*d++ = c;
	}
	return buf;
}

char *
timestamp(time_t t)
{
	static char tstamp[128];
	time_t mytime;
	struct tm ltime;

	mytime = t;
	localtime_r(&mytime, &ltime);
	strftime(tstamp, sizeof(tstamp), "%F %T", &ltime);

	return tstamp;
}

int
interface_is_active(const char *ifname)
{
	int active;
	FILE *fp;
	char buf[256];
#ifdef __linux__
	active = 0;
	snprintf(buf, sizeof(buf), "ip link show %s", ifname);
	fp = popen(buf, "r");
	fgets(buf, sizeof(buf), fp);
	if (strstr(buf, "state UP") != NULL)
		active = 1;
	pclose(fp);
#else
	char *p;

	active = 0;
	snprintf(buf, sizeof(buf), "ifconfig %s", ifname);

#define IFCONFIG_STATUS	"\tstatus: "
	fp = popen(buf, "r");
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		chop(buf);
		p = strstr(buf, IFCONFIG_STATUS);
		if (p != NULL) {
			p += strlen(IFCONFIG_STATUS);
			if (strcmp(p, "active") == 0) {
				active = 1;
				break;
			}
		}
	}
	pclose(fp);
#endif

	return active;
}

struct in_addr *
getifipaddr(const char *ifname, struct in_addr *addr, struct in_addr *netmask)
{
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_in *sin;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return NULL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			sin = (const struct sockaddr_in *)ifa->ifa_addr;
			*addr = sin->sin_addr;
			*netmask = ((const struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
			found = 1;
			break;
		}
	}

	freeifaddrs(ifap);
	return found ? (struct in_addr *)addr : NULL;
}

struct in6_addr *
getifip6addr(const char *ifname, struct in6_addr *addr, struct in6_addr *netmask)
{
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_in6 *sin6;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return NULL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET6) {
			sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
			*addr = sin6->sin6_addr;
			*netmask = ((const struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
			found = 1;
			break;
		}
	}

	freeifaddrs(ifap);
	return found ? (struct in6_addr *)addr : NULL;
}

uint8_t *
getiflinkaddr(const char *ifname, struct ether_addr *addr)
{
#ifdef __linux__
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	int r = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		return NULL;
	}

	close(fd);
	memcpy(addr, &ifr.ifr_hwaddr.sa_data, sizeof(*addr));
	return (uint8_t *)addr;
#else
	struct ifaddrs *ifap, *ifa;
	const struct sockaddr_dl *sdl;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return NULL;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family == AF_LINK) {
			sdl = (const struct sockaddr_dl *) ifa->ifa_addr;
			if ((sdl->sdl_type == IFT_ETHER) &&
			    (sdl->sdl_alen == ETHER_ADDR_LEN)) {

				memcpy(addr, sdl->sdl_data + sdl->sdl_nlen,
				    ETHER_ADDR_LEN);
				found = 1;
				break;
			}
		}
	}

	freeifaddrs(ifap);
	return found ? (uint8_t *)addr : NULL;
#endif
}

int
listentcp(in_addr_t addr, uint16_t port)
{
	int s, on, rc;
	struct sockaddr_in sin;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		warn("socket");
		return -1;
	}
	on = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));

	memset(&sin, 0, sizeof(sin));
#ifndef __linux__
	sin.sin_len = sizeof(sin);
#endif
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = addr;

	rc = bind(s, (struct sockaddr *)&sin, sizeof(sin));
	if (rc < 0) {
		warn("bind");
		close(s);
		return -1;
	}
	rc = listen(s, 5);
	if (rc < 0) {
		warn("listen");
		close(s);
		return -1;
	}

	return s;
}

void
interface_up(const char *ifname)
{
#ifdef __linux__
	char buf[256];
	snprintf(buf, sizeof(buf), "ip link set up dev %s", ifname);
	int r = system(buf);
	(void)r; /* FIXME */
#else
	char buf[256];
	snprintf(buf, sizeof(buf), "ifconfig %s up", ifname);
	int r = system(buf);
	(void)r; /* FIXME */
#endif
}

uint64_t
interface_get_baudrate(const char *ifname)
{
#ifdef __linux__
	int s, rc;
	struct ethtool_value ev = {0};
	struct ethtool_cmd ec = {0};
	struct ifreq ifr;

	ev.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (char *)&ev;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	rc = ioctl(s, SIOCETHTOOL, &ifr);
	if (rc != 0) {
		close(s);
		warn("ioctl(ETHTOOL_GLINK) failed");
		return 0;
	}
	ec.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (char *)&ec;
	rc = ioctl(s, SIOCETHTOOL, &ifr);
	close(s);
	if (rc != 0) {
		warn("ioctl(ETHTOOL_GSET) failed");
		return 0;
	}
	uint32_t speed = ethtool_cmd_speed(&ec);
	if (speed == 0 || speed == (uint16_t)(-1) || speed == (uint32_t)(-1)) {
		warnx("linkspeed unknown");
		return 0;
	}
	return IF_Mbps((uint64_t)speed);
#else
	unsigned int ifindex;
	struct ifmibdata ifmd;
	int name[6];
	size_t len;
	int rv;

	ifindex = if_nametoindex(ifname);

	if (ifindex == 0) {
		warn("Failed to get ifindex\n");
		return 0;
	}

	name[0] = CTL_NET;
	name[1] = PF_LINK;
	name[2] = NETLINK_GENERIC;
	name[3] = IFMIB_IFDATA;
	name[4] = ifindex;
	name[5] = IFDATA_GENERAL;
	len = sizeof(ifmd);

	rv = sysctl(name, 6, &ifmd, &len, 0, 0);
	if (rv < 0) {
		warn("Failed to get ifdata\n");
		return 0;
	}

	return ifmd.ifmd_data.ifi_baudrate;
#endif
}

void
interface_promisc(const char *ifname, int enable, int *old)
{
	struct ifreq ifr;
	int flags, rc;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		warn("socket");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	rc = ioctl(fd, SIOCGIFFLAGS, (caddr_t)&ifr);
	if (rc == -1) {
		fprintf(stderr, "ioctl: SIOCGIFFLAGS: %s\n", strerror(errno));
		goto out;
	}

#ifdef IFF_PPROMISC
	flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);

	if (old != NULL)
		*old = (flags & IFF_PPROMISC);

	if (enable)
		flags |= IFF_PPROMISC;
	else
		flags &= ~IFF_PPROMISC;
	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = flags >> 16;
#else
	flags = ifr.ifr_flags;
	if (old != NULL)
		*old = (flags & IFF_PROMISC);
	if (enable)
		flags |= IFF_PROMISC;
	else
		flags &= ~IFF_PROMISC;
	ifr.ifr_flags = flags;
#endif

	rc = ioctl(fd, SIOCSIFFLAGS, (caddr_t)&ifr);
	if (rc == -1)
		fprintf(stderr, "ioctl: SIOCSIFFLAGS: %s\n", strerror(errno));
out:
	close(fd);
}
