#include <cstring>
#include <cassert>
#include "Neighbor.hpp"

#include <fstream>
#include <time.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <system_error>
#include <arpa/inet.h>
#include <syslog.h>
#include <cassert>
#include <cstring>

void broadcast(int fd, const std::vector<Node> &tree, NeighborSet &neighbors) {
    uint8_t buffer[65536];
    Node n;
    n.addr.s_addr = 0;
    n.children = tree;
    
    auto p = &buffer[SHA_DIGEST_LENGTH];
    *(time_t *)p = time(nullptr);
    p += sizeof(time_t);
    auto len = serialize(n, p, &buffer[65536] - p);
    
    SHA_CTX sha;
    if (!SHA1_Init(&sha))
        throw std::runtime_error("SHA1_Init");
    if (!secret_key.empty()) {
        if (!SHA1_Update(&sha, secret_key.data(), secret_key.length()))
            throw std::runtime_error("SHA1_Update");
    }
    if (!SHA1_Update(&sha, &buffer[SHA_DIGEST_LENGTH], len + sizeof(time_t)))
        throw std::runtime_error("SHA1_Update");
    if (!SHA1_Final(&buffer[0], &sha))
        throw std::runtime_error("SHA1_Final");
    
    assert(!compress_data);
    sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
#ifdef __FreeBSD__
    sin.sin_len = sizeof(sockaddr_in);
#endif
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    NeighborSet to_delete;
    for (auto &neighbor: neighbors) {
        sin.sin_addr.s_addr = htonl(neighbor.addr.s_addr);
        if (sendto(fd, &buffer[0], SHA_DIGEST_LENGTH + sizeof(time_t) + len, 0, (const sockaddr *)&sin, sizeof(sin)) == -1) {
            switch (errno) {
            case EHOSTUNREACH:
            case EHOSTDOWN:
            case ECONNREFUSED:
            case ENETDOWN:
                to_delete.insert(neighbor);
                break;
            default:
                throw std::system_error(errno, std::system_category(), "sendto");
            }
        }
    }
    if (!to_delete.empty()) {
        NeighborSet new_ns;
        std::set_difference(neighbors.begin(), neighbors.end(), to_delete.begin(), to_delete.end(), std::inserter(new_ns, new_ns.begin()), NeighborLess());
        neighbors = std::move(new_ns);
    }
}

Node florp(const uint8_t *buffer, size_t len) {
    if (len <= SHA_DIGEST_LENGTH)
        throw std::runtime_error(std::string("Short packet from "));
    
    SHA_CTX sha;
    if (!SHA1_Init(&sha))
        throw std::runtime_error("SHA1_Init");
    if (!secret_key.empty()) {
        if (!SHA1_Update(&sha, secret_key.data(), secret_key.length()))
            throw std::runtime_error("SHA1_Update");
    }
    if (!SHA1_Update(&sha, &buffer[SHA_DIGEST_LENGTH], len - SHA_DIGEST_LENGTH))
        throw std::runtime_error("SHA1_Update");
    unsigned char md[SHA_DIGEST_LENGTH];
    if (!SHA1_Final(md, &sha))
        throw std::runtime_error("SHA1_Final");
    if (memcmp(&buffer[0], &md[0], SHA_DIGEST_LENGTH))
        throw std::runtime_error(std::string("Invalid signature"));
    
    // timestamp at buffer[SHA_DIGEST_LENGTH]. currently unused.
    return deserialize(&buffer[SHA_DIGEST_LENGTH + sizeof(time_t)], len - SHA_DIGEST_LENGTH - sizeof(time_t));
}

void handle_data(NeighborSet &neighbors, const uint8_t *buffer, ssize_t len, const in_addr &addr) {
    {
        in_addr a { htonl(addr.s_addr) };
        std::ofstream ofs(std::string("/tmp/packet-") + inet_ntoa(a));
        ofs.write((const char *)buffer, len);
    }
    if (len <= SHA_DIGEST_LENGTH)
        throw std::runtime_error(std::string("Short packet from ") + inet_ntoa(addr));
    
    auto &neighbor = [&]() -> const Neighbor & {
        Neighbor n;
        n.addr = addr;
        auto it = neighbors.find(n);
        if (it == neighbors.end())
            throw std::runtime_error(std::string("Packet from unknown neighbor ") + inet_ntoa(addr));
        return *it;
    }();
    
    SHA_CTX sha;
    if (!SHA1_Init(&sha))
        throw std::runtime_error("SHA1_Init");
    if (!secret_key.empty()) {
        if (!SHA1_Update(&sha, secret_key.data(), secret_key.length()))
            throw std::runtime_error("SHA1_Update");
    }
    if (!SHA1_Update(&sha, &buffer[SHA_DIGEST_LENGTH], len - SHA_DIGEST_LENGTH))
        throw std::runtime_error("SHA1_Update");
    unsigned char md[SHA_DIGEST_LENGTH];
    if (!SHA1_Final(md, &sha))
        throw std::runtime_error("SHA1_Final");
    if (memcmp(&buffer[0], &md[0], SHA_DIGEST_LENGTH))
        throw std::runtime_error(std::string("Invalid signature on packet from ") + inet_ntoa(addr));
    
    // timestamp at buffer[SHA_DIGEST_LENGTH]. currently unused.
    neighbor.tree = deserialize(&buffer[SHA_DIGEST_LENGTH + sizeof(time_t)], len - SHA_DIGEST_LENGTH - sizeof(time_t));
    neighbor.tree->addr = addr;
    neighbor.last_seen = time(nullptr);
}

void nuke_trees_for_iface(NeighborSet &neighbors, const std::string &iface) {
    for (auto &neighbor: neighbors)
        if (neighbor.iface == iface)
            neighbor.tree.reset();
}

bool nuke_old_trees(NeighborSet &neighbors, int num_seconds) {
    bool res = false;
    auto now = time(nullptr);
    for (auto &neighbor: neighbors)
        if (neighbor.last_seen < now - num_seconds) {
            res = true;
            neighbor.tree.reset();
        }
    return res;
}

std::pair<RouteSet, std::vector<Node>> derive_routes_and_mytree(const RouteSet &direct_nets, const NeighborSet &neighbors, const InAddrSet &default_gateways, const std::set<std::string> &zero_hop_ifaces) {
    std::vector<Node> trees;
    for (auto &neighbor: neighbors) {
        if (!neighbor.tree)
            continue;
        // the top node here is actually still a placeholder. only the children are valid there.
        Node n;
        n.addr = neighbor.addr;
        n.ethernet = zero_hop_ifaces.count(neighbor.iface);
        n.gateway = default_gateways.count(neighbor.addr);
        n.children = neighbor.tree->children;
        trees.push_back(std::move(n));
    }

    auto [tree, routes, default_gateway] = merge(trees);
    routes = aggregate(routes);
    
    if (default_gateway.s_addr != INADDR_ANY) {
        Route default_route;
        default_route.addr.s_addr = INADDR_ANY;
        default_route.netmask = 0;
        default_route.gateway = default_gateway;
        routes.insert(std::move(default_route));
    }
    
    RouteSet to_erase;
    for (auto &direct: direct_nets) {
        for (auto &r: routes)
            if (matches(direct, r.addr))
                to_erase.insert(r);
    }
    if (!to_erase.empty()) {
        RouteSet new_routes;
        std::set_difference(routes.begin(), routes.end(), to_erase.begin(), to_erase.end(), std::inserter(new_routes, new_routes.begin()), RouteLess());
        routes = std::move(new_routes);
    }
    
    return { std::move(routes), std::move(tree.children) };
}

bool check_reachable(const Neighbor &neighbor, Iface &iface) {
    if (!neighbor.macaddr) {
        auto arptable = get_arptable(neighbor.iface);
        auto it = arptable.find(neighbor.addr);
        if (it != arptable.end())
            neighbor.macaddr = it->second;
    }
    auto reachable = neighbor.macaddr && is_reachable(iface, *neighbor.macaddr);
    if (!reachable) {
        neighbor.tree.reset();
        neighbor.last_seen = 0;
    }
    return reachable;
}
