#include "Route.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <sstream>
#include <vector>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <memory>
#include <cstring>
#include <cstddef>

bool includes(const Route &a, const Route &b) {
    if (a.netmask > b.netmask)
        return false;
    auto m = bitmask(a.netmask);
    return (a.addr.s_addr & m) == (b.addr.s_addr & m);
}

bool matches(const Route &route, const in_addr &addr) {
    auto m = bitmask(route.netmask);
    return (route.addr.s_addr & m) == (addr.s_addr & m);
}

std::string show(const Route &route) {
    return std::string(inet_ntoa(route.addr)) + "/" + std::to_string(route.netmask) + " -> " + inet_ntoa(route.gateway);
}

std::string show(const RouteSet &routes) {
    std::ostringstream oss;
    oss << "Route table:" << std::endl;
    for (auto &route: routes)
         oss << "\t" << show(route) << std::endl;
    return oss.str();
}

RouteSet aggregate(RouteSet &rs) {
    RouteSet res;

    std::vector<Route> routes(rs.begin(), rs.end());
    for (size_t i = 0; i < routes.size(); ) {
        auto &route = routes[i];
        if (route.netmask == minimum_netmask) {
            res.insert(std::move(route));
            routes.erase(routes.begin() + i);
            continue;
        }
        if (route.addr.s_addr == route.gateway.s_addr && route.netmask == 32) {
            routes.erase(routes.begin() + i);
            continue;
        }

        while (route.netmask > minimum_netmask) {
            --route.netmask;
            size_t j;
            for (j = i + 1; j < routes.size(); j++) {
                auto &other_route = routes[j];
                if (route.gateway.s_addr != other_route.addr.s_addr && includes(route, other_route))
                    break;
            }
            if (j < routes.size()) {
                ++route.netmask;
                res.insert(std::move(route));
                routes.erase(routes.begin() + i);
                break;
            }
            for (size_t j = routes.size() - 1; j > i + 1; i--) {
                auto &other_route = routes[j];
                if (includes(route, other_route)) {
                    routes.erase(routes.begin() + j);
                }
            }
        }
    }
    return res;
}

std::tuple<RouteSet, RouteSet, RouteSet> diff(const RouteSet &old_routes, const RouteSet &new_routes) {
    RouteSet deletes, adds, changes;
    auto old_it = old_routes.begin();
    auto new_it = new_routes.begin();

    RouteLess l;

    while (true) {
        if (old_it == old_routes.end()) {
            std::copy(new_it, new_routes.end(), std::inserter(adds, adds.begin()));
            break;
        }
        if (new_it == new_routes.end()) {
            std::copy(old_it, old_routes.end(), std::inserter(deletes, deletes.begin()));
            break;
        }
        if (l(*old_it, *new_it))
            deletes.insert(*old_it);
        else if (l(*new_it, *old_it))
            adds.insert(*new_it);
        else if (old_it->gateway.s_addr != new_it->gateway.s_addr)
            changes.insert(*new_it);
        ++old_it;
        ++new_it;
    }
    return { std::move(deletes), std::move(adds), std::move(changes) };
}

#ifdef __FreeBSD__
static size_t routemsg_add(uint8_t *buffer, int type, const Route &route) {
	struct rt_msghdr *msghdr;
	struct sockaddr_in *addr;
	static int seq = 1;

	msghdr = (struct rt_msghdr *)buffer;	
	memset(msghdr, 0, sizeof(struct rt_msghdr));
	msghdr->rtm_version = RTM_VERSION;
	msghdr->rtm_type = type;
	msghdr->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	msghdr->rtm_pid = 0;
	msghdr->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_DYNAMIC;
	msghdr->rtm_seq = seq++;

	addr = (struct sockaddr_in *)(msghdr + 1);
#define ADD(x) \
	memset(addr, 0, sizeof(struct sockaddr_in));	\
	addr->sin_len = sizeof(struct sockaddr_in);	\
	addr->sin_family = AF_INET;			\
	addr->sin_addr.s_addr = htonl(x);		\
	addr++;

	ADD(route.addr.s_addr & bitmask(route.netmask));
    ADD(route.gateway.s_addr);
	ADD(bitmask(route.netmask));

	/*
	 * for some reason, the sin_len for the netmask's sockaddr_in should
	 * not be the length of the sockaddr_in at all, but the offset of
	 * the sockaddr_in's last non-zero byte. I don't know why. From
	 * the last byte of the sockaddr_in, step backwards until there's a
	 * non-zero byte under the cursor, then set the length.
	 */
	addr--;
	for (auto p = (const uint8_t *)(addr + 1) - 1; p > (const uint8_t *)addr; p--)
        if (*p) {
            addr->sin_len = p - (const uint8_t *)addr + 1;
            break;
        }
	addr->sin_family = 0; /* just to be totally in sync with /usr/sbin/route */

	msghdr->rtm_msglen = (const uint8_t *)addr +
				ROUNDUP(addr->sin_len)
				- buffer;
	
	return msghdr->rtm_msglen;
}
#endif

void commit(int routefd, RouteSet deletes, RouteSet adds, RouteSet changed) {
#ifdef __FreeBSD__
    auto buflen = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);
    uint8_t buffer[buflen];

    RouteLess l;

    for (int i = 0; i < 5; i++) {
        for (auto &add: adds) {
            auto len = routemsg_add(&buffer[0], RTM_ADD, add);
            write(routefd, &buffer[0], len);
        }

        for (auto &del: deletes) {
            auto len = routemsg_add(&buffer[0], RTM_DELETE, del);
            write(routefd, &buffer[0], len);
        }

        for (auto &change: changed) {
            auto len = routemsg_add(&buffer[0], RTM_CHANGE, change);
            write(routefd, &buffer[0], len);
        }
        changed.clear();

        if (i < 5) {
            auto rs = fetch(routefd);
            RouteSet remaining_adds, remaining_deletes;
            std::set_difference(adds.begin(), adds.end(), rs.begin(), rs.end(), std::inserter(remaining_adds, remaining_adds.begin()), l);
            std::set_intersection(deletes.begin(), deletes.end(), rs.begin(), rs.end(), std::inserter(remaining_deletes, remaining_deletes.begin()), l);
            if (remaining_adds.empty() && remaining_deletes.empty())
                break;
            adds = std::move(remaining_adds);
            deletes = std::move(remaining_deletes);
        }
    }
#endif
}

RouteSet fetch(int routefd) {
    RouteSet res;

#ifdef __FreeBSD__

    /* Reference code: /usr/src/sbin/route/route.c - flushroutes(argc, argv) */
    int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };
    size_t needed;
    std::unique_ptr<uint8_t[]> buf;
    const uint8_t *p, *lim, *p2, *lim2;
    struct rt_msghdr *rtm;
    struct sockaddr_in *sin;

    if (sysctl(mib, 6, 0, &needed, 0, 0) == -1)
        throw std::system_error(errno, std::system_category(), "fetch of route table size");
    buf.reset(new uint8_t[needed]);
    if (sysctl(mib, 6, &buf[0], &needed, 0, 0) == -1)
        throw std::system_error(errno, std::system_category(), "route retrieval");

    lim = &buf[needed];
    for (p = &buf[0]; p < lim; p += rtm->rtm_msglen) {
        rtm = (struct rt_msghdr *)p;
        if ((rtm->rtm_flags & RTF_GATEWAY) == 0 ||
            (rtm->rtm_flags & RTF_DYNAMIC) == 0 || 
            (rtm->rtm_addrs & RTA_NETMASK) == 0)
            continue;
        sin = (struct sockaddr_in *)(rtm + 1);
        if (sin->sin_family != AF_INET)
            continue;

        Route r;
        r.addr = sin->sin_addr;
        if (r.addr.s_addr != 0 && (r.addr.s_addr < min_routable.s_addr || r.addr.s_addr > max_routable.s_addr))
            continue; // not one of ours
        sin++;
    
        r.gateway = sin->sin_addr;
        sin++;

        /* netmask. bwurk, why the fsck all this fudging with
           ->sin_len?! */
        r.netmask = 0;
        lim2 = (const uint8_t *)sin + sin->sin_len;
        p2 = (const uint8_t *)&sin->sin_addr.s_addr;
        for (; p2 < lim2; p2++)
          r.netmask += __builtin_popcount(*p2);

        res.insert(std::move(r));
    }
#endif
    return res;
}

void flush(int routefd) {
    commit(routefd, fetch(routefd), {}, {});
}
