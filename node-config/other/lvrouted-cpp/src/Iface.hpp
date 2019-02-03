#ifndef IFACE_HPP
#define IFACE_HPP

#include "common.hpp"
#include "MAC.hpp"

#include <optional>

enum class IfaceType {
    Wired,      // no notion of association
	WifiClient, // client of a master, can check for association *)
	WifiMaster, // master of several clients, can check the list of
			    // associated stations for a specific client
};

struct Iface {
    explicit Iface(std::string);
    
    std::string name;
    IfaceType type; 

    int last_associated_update;
    int last_arp_update;

    std::optional<EtherAddrSet> arp_table;
    std::optional<EtherAddrSet> associated;
    std::optional<bool> is_associated;
};

void update_interface(Iface &);

bool in_arptable(Iface &, struct ether_addr &);
bool is_reachable(Iface &, struct ether_addr &);

bool is_nanostation(const Iface &);

#endif // IFACE_HPP
