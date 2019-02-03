#ifndef MAC_HPP
#define MAC_HPP

#include "common.hpp"

#include <set>
#include <memory>

#include <sys/types.h>
#include <net/ethernet.h>

using ArpTable = InAddrMap<ether_addr>;

struct EtherAddrLess {
    bool operator()(const ether_addr &one, const ether_addr &other) const {
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
#ifdef __FreeBSD__
#  define OCTET octet
#else
#  define OCTET ether_addr_octet
#endif
            if (one.OCTET[i] < other.OCTET[i])
                return true;    
            if (one.OCTET[i] > other.OCTET[i])
                return false;
#undef OCTET
        }
        return false;
    }
};
using EtherAddrSet = std::set<ether_addr, EtherAddrLess>;

extern std::map<std::string, ArpTable> arptables;
extern int arptables_last_update;

extern ArpTable get_arptable(const std::string &interface);
extern std::string show_arptable(const ArpTable &);

#endif // MAC_HPP
