#include "Iface.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <system_error>

#include <sys/ioctl.h>
#include <net/if.h>
#ifndef __linux
#  include <net80211/ieee80211_ioctl.h>
#  include <net/if_media.h>
#endif

struct Popen {
    Popen(const std::string &cmd) {
        stream = popen(cmd.data(), "r");
    }
    ~Popen() {
        if (stream)
            pclose(stream);
    }
    FILE *stream;
};

Iface::Iface(std::string name_): name(std::move(name_)) {
    auto p = Popen("/sbin/ifconfig " + name);
    if (!p.stream)
        throw std::system_error(errno, std::system_category(), "spawn ifconfig");
    char buffer[BUFSIZ];
    while (!feof(p.stream)) {
        if (fgets(buffer, BUFSIZ, p.stream) && strncmp(buffer, "\tmedia: ", 8) == 0) {
            if (strstr(buffer, "hostap"))
                type = IfaceType::WifiMaster;
            else if (strstr(buffer, "Wireless"))
                type = IfaceType::WifiClient;
            else
                type = IfaceType::Wired;
        }
    }
}

static EtherAddrSet get_associated_stations(const std::string &iface) {
#ifdef __FreeBSD__
	int i;
	/* FreeBSD 6.0 and up (hopefully), swiped from ifconfig */
    /* Reference code ???: /usr/src/sbin/ifconfig/ifieee80211.c - list_stations(int s)' */
	int n;
	union {
		struct ieee80211req_sta_req req;
		uint8_t buf[24*1024];
	} u;
	struct ieee80211req ireq;
	int len;
	uint8_t *cp;

	FileDescriptor sockfd(socket(AF_INET, SOCK_DGRAM, 0));
	if (sockfd.fd == -1)
        throw std::system_error(errno, std::system_category(), "socket for get_associated_stations");
	/* Set up the request */
	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, iface.data(), sizeof(ireq.i_name));
	ireq.i_type = IEEE80211_IOC_STA_INFO;
	/*
	 * This is apparently some sort of filter to what addresses we're
     * interested in, and all 0xff's says that we want all of them.
	 */
	memset(u.req.is_u.macaddr, 0xff, IEEE80211_ADDR_LEN);
	ireq.i_data = &u;
	ireq.i_len = sizeof(u);
	if (ioctl(sockfd.fd, SIOCG80211, &ireq) < 0)
		throw std::system_error(errno, std::system_category(), "SIOCG80211");
	len = ireq.i_len;

	for (n = 0, cp = (uint8_t *)u.req.info; len >= sizeof(struct ieee80211req_sta_info); n++) {
		struct ieee80211req_sta_info *si;
		si = (struct ieee80211req_sta_info *) cp;
		cp += si->isi_len, len -= si->isi_len;
	}

    EtherAddrSet res;

	len = ireq.i_len;
	for (i = 0, cp = (uint8_t *)u.req.info; len >= sizeof(struct ieee80211req_sta_info); i++) {
		struct ieee80211req_sta_info *si;

		si = (struct ieee80211req_sta_info *) cp;
        struct ether_addr addr;
        memcpy(addr.octet, si->isi_macaddr, ETHER_ADDR_LEN);
        res.insert(std::move(addr));

		cp += si->isi_len, len -= si->isi_len;
	}

    return res;
#else
    return {};
#endif
}

/* reference code: /usr/src/sbin/ifconfig/ifmedia.c - media_status(int s) */
#ifdef __FreeBSD__
/* stuff ifm_status in ints[0] and ifm_active in ints[1] */
static void ifstatus(const char *iface, int *ints) {
	struct ifmediareq ifmr;

    FileDescriptor sockfd(socket(AF_INET, SOCK_DGRAM, 0));
	if (sockfd.fd == -1)
        throw std::system_error(errno, std::system_category(), "socket for ifstatus");

	memset(&ifmr, 0, sizeof(ifmr));
	strncpy(ifmr.ifm_name, iface, sizeof(ifmr.ifm_name));

	if (ioctl(sockfd.fd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
        throw std::system_error(errno, std::system_category(), "Interface doesn't support SIOC{G,S}IFMEDIA.");
	if (ifmr.ifm_count == 0)
        throw std::system_error(errno, std::system_category(), "huh, no media types?");

    int media_list[ifmr.ifm_count];
	ifmr.ifm_ulist = media_list;

	if (ioctl(sockfd.fd, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
        throw std::system_error(errno, std::system_category(), "SIOCGIFMEDIA");

	ints[0] = ifmr.ifm_status;
	ints[1] = ifmr.ifm_active;
}
#endif

void update_interface(Iface &iface) {
    auto now = time(nullptr);
    if ((iface.type == IfaceType::WifiMaster && !iface.associated) ||
        (iface.last_associated_update + interface_association_update_interval < now)) {
        switch (iface.type) {
        case IfaceType::WifiMaster:
            iface.associated = get_associated_stations(iface.name);
            break;
        case IfaceType::WifiClient: {
#ifdef __FreeBSD__
            int i[2];
            ifstatus(iface.name.data(), i);
            iface.is_associated = (i[0] & IFM_AVALID) &&
                   ((IFM_TYPE(i[1]) != IFM_IEEE80211 || i[0] & IFM_ACTIVE));
#endif
            break;
        }
        default:
            break;
        }
        iface.last_associated_update = now;
    }
    if (iface.last_arp_update + interface_arptable_update_interval < now) {
        EtherAddrSet addrs;
        for (auto &[ipaddr, ethaddr]: get_arptable(iface.name))
            addrs.insert(ethaddr);
        iface.arp_table = std::move(addrs);
        iface.last_arp_update = now;
    }
}

bool in_arptable(Iface &iface, struct ether_addr &addr) {
    update_interface(iface);
    return iface.arp_table && iface.arp_table->count(addr) > 0;
}

bool is_reachable(Iface &iface, struct ether_addr &addr) {
    update_interface(iface);

    switch (iface.type) {
    case IfaceType::Wired:
        return true;
    case IfaceType::WifiClient:
        return iface.is_associated && *iface.is_associated;
    case IfaceType::WifiMaster:
        return iface.associated ? iface.associated->count(addr) != 0 : false;
    default: assert(false);
    }
}

bool is_nanostation(const Iface &iface) {
    return iface.arp_table && std::find_if(iface.arp_table->begin(),
                                           iface.arp_table->end(),
                                           [](auto a) {
#ifdef __FreeBSD__
        return is_nanostation(a.octet);
#else
        return false;
#endif
    }) != iface.arp_table->end();
}
