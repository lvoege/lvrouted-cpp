#ifndef NEIGHBOR_HPP
#define NEIGHBOR_HPP

#include <string>
#include <netinet/in.h>
#include <optional>
#include <sys/types.h>
#include <net/ethernet.h>
#include <set>

#include "Route.hpp"
#include "Tree.hpp"
#include "Iface.hpp"

struct Neighbor {
    std::string iface;
    in_addr addr;
    mutable std::optional<ether_addr> macaddr;
    mutable int last_seen;
    int seqno;
    mutable std::optional<Node> tree;
};

struct NeighborLess {
    bool operator()(const Neighbor &one, const Neighbor &other) const {
        return one.addr.s_addr < other.addr.s_addr;
    }
};
using NeighborSet = std::set<Neighbor, NeighborLess>;

// TODO: broadcast() and handle_data() are lopsided. broadcat() allocates a buffer and handle_data() takes an already allocated one

/* Broadcast the given list of tree nodes to the given Set of neighbors over
   the given file descriptor. */
void broadcast(int fd, const std::vector<Node> &tree, NeighborSet &);

/* Given a set of neighbors, data in a string and the sockaddr it came from,
   handle it. Verify the signature, find the neighbor associated with the
   address, verify the sequence number, parse the tree and mark the time. */
void handle_data(NeighborSet &, const uint8_t *, ssize_t, const in_addr &);

/* Given a list of neighbors and interface i, invalidate the trees
   for all the neighbors on that interface */
void nuke_trees_for_iface(NeighborSet &, const std::string &);

/* Given a list of neighbors and a number of seconds, invalidate the 
   trees of all neighbors not heard from since numsecs ago */
bool nuke_old_trees(NeighborSet &, int num_seconds);

/* From the given set of direct IPs, a list of neighbors, a list of default
   gateways on the network to look out for (and indeed insert a default route
   for the nearest of these) plus a set of interfaces that count as zero-hop
   links, derive a list of (unaggregated) routes and a merged tree. */
std::pair<RouteSet, std::vector<Node>> derive_routes_and_mytree(const RouteSet &, const NeighborSet &, const InAddrSet &, const std::set<std::string> &);

/* Check if the given neighbor is reachable over the given Iface.t. If it
   isn't, set the neighbor's tree to None. */
bool check_reachable(const Neighbor &, Iface &);

Node florp(const uint8_t *buffer, size_t len);

#endif // NEIGHBOR_HPP
