#include "MAC.hpp"

#include <sstream>
#include <system_error>

#include <cassert>
#include <cstddef>
#include <ctime>

#include <arpa/inet.h>
#ifndef __linux__
#  include <net/if_dl.h>
#  include <net/if_types.h>
#else
#  include <netinet/ether.h>
#endif
#include <net/if.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <sys/sysctl.h>

std::map<std::string, ArpTable> arptables;
int arptables_last_update = -1;

ArpTable get_arptable(const std::string &interface) {
    auto now = time(nullptr);
    if (arptables_last_update + arptable_update_interval < now) {
        arptables.clear();
#ifdef __FreeBSD__
        int mib[6], numentries;
        size_t needed;
        std::unique_ptr<uint8_t[]> buf;
        const uint8_t *lim, *next;
        struct rt_msghdr *rtm;
        struct sockaddr_inarp *sin2;
        struct sockaddr_dl *sdl;
        char ifname[IF_NAMESIZE];

        mib[0] = CTL_NET;
        mib[1] = PF_ROUTE;
        mib[2] = 0;
        mib[3] = AF_INET;
        mib[4] = NET_RT_FLAGS;
        mib[5] = RTF_LLDATA;
        if (sysctl(mib, 6, NULL, &needed, 0, 0) < 0)
            throw std::system_error(errno, std::system_category(), "fetch of arp table size");
        if (needed) {
            buf.reset(new uint8_t[needed]);
            if (sysctl(mib, 6, &buf[0], &needed, 0, 0) < 0)
                throw std::system_error(errno, std::system_category(), "fetch of arp table");
            numentries = 0;
            lim = &buf[needed];
            for (next = &buf[0]; next < lim; next += rtm->rtm_msglen) {
                rtm = (struct rt_msghdr *)next;
                sin2 = (struct sockaddr_inarp *)(rtm + 1);
                sdl = (struct sockaddr_dl *)((char *)sin2 +
                    ROUNDUP(sin2->sin_len)
                );
                if (sdl->sdl_alen == 0)
                    continue; /* incomplete entry */
                if ((sdl->sdl_type != IFT_ETHER  && sdl->sdl_type != IFT_L2VLAN) ||
                    sdl->sdl_alen != ETHER_ADDR_LEN)
                    continue; /* huh? */
                if (if_indextoname(sdl->sdl_index, ifname) == 0)
                    continue; /* entry without interface? shouldn't happen */
                in_addr a { ntohl(sin2->sin_addr.s_addr) };
                arptables[ifname].emplace(a, *((struct ether_addr *)LLADDR(sdl)));
            }
        }
#else
        assert(0);
#endif
    }
    if (auto it = arptables.find(interface); it != arptables.end())
        return it->second;
    return {};
}

std::string show_arptable(const ArpTable &table) {
    std::ostringstream oss;
    oss << "Arptable: " << std::endl;
    for (auto &[inaddr, ethaddr]: table)
        oss << "\t" << inet_ntoa(inaddr) << " -> " << ether_ntoa(&ethaddr) << std::endl;
    return oss.str();
}
