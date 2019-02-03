#include <cassert>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <memory>
#include <cstdio>
#include <syslog.h>
#include <unistd.h>
#include <iostream>

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <ifaddrs.h>
#include <net/route.h>
#include <net/if.h>

#include "common.hpp"
#include "Iface.hpp"
#include "Route.hpp"
#include "Neighbor.hpp"
#include "Tree.hpp"

static bool this_is_a_gateway = false;
static InAddrSet default_gateways;
static bool quit = false;
static NeighborSet neighbors;
static InAddrSet unreachable_neighbors;
static std::map<std::string, Iface> ifaces;
static int last_time = 0;
struct NodeLess {
    bool operator()(const Node &one, const Node &other) const {
        return one.addr.s_addr < other.addr.s_addr;
    }
};
static std::set<Node, NodeLess> direct;
static RouteSet direct_nets;
static std::set<std::string> zero_hop_ifaces;

static void version_info() {
    std::cout << "version " << SVN_VERSION << std::endl;
}

static bool changes_in_reachability() {
    InAddrSet new_unreachable;
    for (auto &neighbor: neighbors) {
        auto it = ifaces.find(neighbor.iface);
        assert(it != ifaces.end());
        if (!check_reachable(neighbor, it->second)) {
            new_unreachable.insert(neighbor.addr);
            if (unreachable_neighbors.count(neighbor.addr) == 0)
                syslog(LOG_DEBUG, "Neighbor %s became unreachable", inet_ntoa(neighbor.addr));
        }
    }
    InAddrSet diff;
    std::set_symmetric_difference(new_unreachable.begin(), new_unreachable.end(),
                                unreachable_neighbors.begin(), unreachable_neighbors.end(),
                                  std::inserter(diff, diff.begin()), InAddrLess());
    unreachable_neighbors = std::move(new_unreachable);
    return !diff.empty();
}

static void broadcast_run(int udpfd, int routefd) {
    syslog(LOG_DEBUG, "Starting broadcast run");
    last_time = time(nullptr);
    for (auto &neighbor: neighbors) {
        std::string fname("/tmp/lvrouted.tree-");
        fname += inet_ntoa(neighbor.addr);
        if (neighbor.tree) {
            std::ofstream ofs(fname);
            ofs << to_string(neighbor.tree->children);
        } else unlink(fname.data());
        
    }
    
    auto [new_routes, new_nodes] = derive_routes_and_mytree(direct_nets, neighbors, default_gateways, zero_hop_ifaces);
    new_nodes.insert(new_nodes.end(), direct.begin(), direct.end());
    
    {
        std::ofstream ofs("/tmp/lvrouted.mytree");
        ofs << to_string(new_nodes) << std::endl;
    }
    
    broadcast(udpfd, new_nodes, neighbors);
 
    if (real_route_updates) {
        auto [deletes, adds, changes] = diff(fetch(routefd), new_routes);
        syslog(LOG_DEBUG, "Committing %zu deletes, %zu adds and %zu changes", deletes.size(), adds.size(), changes.size());
        commit(routefd, std::move(deletes), std::move(adds), std::move(changes));
    }
    syslog(LOG_DEBUG, "Done with broadcast run");
}

static void periodic_check(int udpfd, int routefd) {
    auto now = time(nullptr);
    auto expired = nuke_old_trees(neighbors, timeout);
    if (changes_in_reachability() || expired || (now - last_time) > broadcast_interval) {
        broadcast_run(udpfd, routefd);
    }
}

static void parse_default_gateways(std::string s) {
    size_t pos;
    while ((pos = s.find(',')) != std::string::npos) {
        auto ss = s.substr(0, pos);
        in_addr a;
        if (inet_aton(ss.data(), &a) == 0) {
            std::cerr << "Invalid gateway address: " << ss << std::endl;
            exit(1);
        }
        default_gateways.insert(std::move(a));
        s.erase(0, pos + 1);
    }
}

static void read_config() {
    direct.clear();
    direct_nets.clear();
    ifaces.clear();
    neighbors.clear();
    unreachable_neighbors.clear();
    
    syslog(LOG_DEBUG, "Reading config");
    ifaddrs *ifa;
    if (getifaddrs(&ifa) < 0)
        throw std::system_error(errno, std::system_category(), "getifaddrs()");
    std::unique_ptr<ifaddrs, std::function<void (ifaddrs *)>> g(ifa, [](ifaddrs *a) { freeifaddrs(a); });
    for (auto p = ifa; p != nullptr; p = p->ifa_next) {
        if (p->ifa_addr->sa_family != AF_INET)
            continue;
        auto sin = (const sockaddr_in *)p->ifa_addr;
        auto addr = ntohl(sin->sin_addr.s_addr);
        if (!addr_in_range(addr))
            continue;
        Node n;
        n.addr.s_addr = addr;
        n.ethernet = false;
        n.gateway = this_is_a_gateway;
        auto maskaddr = (const sockaddr_in *)p->ifa_netmask;
        auto masklen = __builtin_popcount(maskaddr->sin_addr.s_addr);
        auto it = direct.find(n);
        if (it == direct.end()) {
            direct.insert(std::move(n));
            Route r;
            r.addr.s_addr = addr;
            r.netmask = masklen;
            r.gateway.s_addr = addr;
            direct_nets.insert(std::move(r));
        }
        
        auto &iface = ifaces.try_emplace(p->ifa_name, p->ifa_name).first->second;
        
        if (masklen >= interlink_netmask && masklen < 32) {
            // for all addresses in this block
            auto mask = bitmask(masklen);
            auto masked = addr & mask;
            for (auto a = masked + 1; ((a + 1) & mask) == masked; ++a) {
                if (a != sin->sin_addr.s_addr) {
                    Neighbor n;
                    n.iface = iface.name;
                    n.addr.s_addr = a;
                    n.seqno = 0;
                    n.last_seen = -1;
                    neighbors.insert(std::move(n));
                }
            }
        }
    }
    syslog(LOG_DEBUG, "Done reading config");
}

int main(int argc, char *argv[]) {
    setlogmask(LOG_EMERG | LOG_ALERT | LOG_CRIT | LOG_ERR | LOG_WARNING);
    if (0) {
        try {
            uint8_t buffer[65536];
            std::vector<Node> trees;
            in_addr a = min_routable;
            for (int i = 1; i < argc; i++) {
                std::ifstream ifs(argv[i]);
                ifs.read((char *)&buffer[0], 65536);
                trees.push_back(deserialize(&buffer[24], ifs.gcount() - 24));
                trees.back().addr = a;
                a.s_addr++;
            }
            auto [merged, foo, bar] = merge(trees);
            std::cout << "MERGED " << to_string(merged.children) << std::endl;
            return 0;
        } catch (std::exception &ex) {
            std::cout << "EEP " << ex.what() << std::endl;
            return 1;
        }
    }
    
    openlog(nullptr, LOG_PERROR | LOG_PID, LOG_DAEMON);
    int c;
    while ((c = getopt(argc, argv, "a:b:c:d:flm:p:s:t:uvz:g")) != -1) {
        switch (c) {
        case 'a':
            alarm_timeout = std::stoi(optarg);
            break;
        case 'b':
            broadcast_interval = std::stoi(optarg);
            break;
        case 'c':
            configfile = optarg;
            break;
        case 'd':
            //loglevel
            break;
        case 'f':
            stay_in_foreground = true;
            break;
        case 'l':
            use_syslog = true;
            break;
        case 'm':
            minimum_netmask = std::stoi(optarg);
            break;
        case 'p':
            port = std::stoi(optarg);
            break;
        case 's':
            secret_key = optarg;
            break;
        case 't':
            // tmpdir
            break;
        case 'u':
            real_route_updates = true;
            break;
        case 'v':
            version_info();
            break;
        case 'z':
            parse_default_gateways(optarg);
            break;
        case 'g':
            this_is_a_gateway = true;
            break;
        case '?':
            std::cerr << "Unknown or illegal option '" << optopt << "'" << std::endl;
            exit(1);
        }
    }
    
    {
        rlimit rlimit;
        if (getrlimit(RLIMIT_DATA, &rlimit) == 0) {
            rlimit.rlim_max = 10 * 1024 * 1024;
            setrlimit(RLIMIT_DATA, &rlimit);
        }
        if (getrlimit(RLIMIT_CORE, &rlimit) == 0) {
            rlimit.rlim_max = 10 * 1024 * 1024;
            setrlimit(RLIMIT_CORE, &rlimit);
        }
    }
    
    read_config();
    
    if (!stay_in_foreground && daemon(0, 0) < 0) {
        std::cerr << "Couldn't daemonize: " << strerror(errno) << std::endl;
        return 1;
    }
    
    FileDescriptor udpsock(socket(PF_INET, SOCK_DGRAM, 0));
    if (udpsock.fd == -1) {
        std::cerr << "Couldn't open UDP socket: " << strerror(errno) << std::endl;
        return 1;
    }
    if (int i = 1; setsockopt(udpsock.fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(int)) < 0) {
        std::cerr << "Couldn't setsockopt(): " << strerror(errno) << std::endl;
        return 1;
    }
    sockaddr_in sin { 0 };
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
#ifdef __FreeBSD
    sin.sin_len = sizeof(sin);
#endif
    sin.sin_port = htons(port);
    if (bind(udpsock.fd, (const sockaddr *)&sin, sizeof(sin)) < 0) {
        std::cerr << "Couldn't bind(): " << strerror(errno) << std::endl;
        return 1;
    }
    
    FileDescriptor rtsock(socket(PF_ROUTE, SOCK_RAW, 0));
    if (rtsock.fd == -1) {
        std::cerr << "Couldn't open routing socket: " << strerror(errno) << std::endl;
        return 1;
    }
#ifdef __FreeBSD__
    if (int i = 1; setsockopt(rtsock.fd, SOL_SOCKET, SO_USELOOPBACK, &i, sizeof(i)) < 0) {
        std::cerr << "Couldn't setsockopt(): " << strerror(errno) << std::endl;
        return 1;
    }
#endif
    
    uint8_t buffer[65536];
    int last_periodic_check = 0;
    fd_set read_fds;
    while (!quit) {
        syslog(LOG_DEBUG, "Main loop");
        try {
            FD_ZERO(&read_fds);
            FD_SET(udpsock.fd, &read_fds);
            FD_SET(rtsock.fd, &read_fds);
            timeval timeout_timer { 0 };
            timeout_timer.tv_sec = alarm_timeout;
            auto foo = select(std::max(udpsock.fd, rtsock.fd) + 1, &read_fds, nullptr, nullptr, &timeout_timer);
            if (foo < 0) {
                syslog(LOG_WARNING, "Couldn't select(): %s", strerror(errno));
                return 1;
            }
            syslog(LOG_DEBUG, "SELECT %d\n", foo);
            if (FD_ISSET(udpsock.fd, &read_fds)) {
                struct sockaddr_in sin;
                socklen_t sin_len = sizeof(sin);
                auto len = recvfrom(udpsock.fd, &buffer[0], sizeof(buffer), 0, (struct sockaddr *)&sin, &sin_len);
                if (len < 0)
                    syslog(LOG_WARNING, "Error reading UDP message: %s", strerror(errno));
                else {
                    syslog(LOG_DEBUG, "Received packet from address %s", inet_ntoa(sin.sin_addr));
                    sin.sin_addr.s_addr = ntohl(sin.sin_addr.s_addr);
                    handle_data(neighbors, buffer, len, sin.sin_addr);
                }
            }
            if (FD_ISSET(rtsock.fd, &read_fds)) {
                auto len = read(rtsock.fd, &buffer[0], sizeof(buffer));
                if (len < 0)
                    syslog(LOG_WARNING, "Error reading route message: %s", strerror(errno));
                else {
                    syslog(LOG_DEBUG, "Received routing message");
#ifdef __FreeBSD__
                    auto ifa = (const ifa_msghdr *)&buffer[0];
                    auto p = (const uint8_t *)(ifa + 1);
                    bool okay = true;
                    int masklen = -1;
                    in_addr addr { INADDR_ANY };
                    for (int i = RTA_DST; i <= RTA_BRD && okay; i <<= 1) {
                        if ((ifa->ifam_addrs & i) == 0)
                            continue;
                        auto sin = (const struct sockaddr_in *)(ifa + 1);
                        okay = sin->sin_family != AF_INET;
                        switch (i) {
                        case RTA_NETMASK:
                            masklen = __builtin_popcount(sin->sin_addr.s_addr);
                            break;
                        case RTA_IFA:
                            addr = sin->sin_addr;
                            break;
                        }
                        p += ROUNDUP(sin->sin_len);
                    }
                    if (okay) {
                        switch (ifa->ifam_type) {
                        case RTM_NEWADDR:
                            
                        case RTM_DELADDR:
                            
                        default: break;
                        }
                    }
                    
#endif
                }
            }
            auto now = time(nullptr);
            if (last_periodic_check < now - alarm_timeout) {
                periodic_check(udpsock.fd, rtsock.fd);
                last_periodic_check = now;
            }
        } catch (std::runtime_error &ex) {
            syslog(LOG_ERR, "Got runtime error: %s\n", ex.what());
        } catch (std::exception &ex) {
            syslog(LOG_CRIT, "Got fatal error: %s\n", ex.what());
            exit(1);
        } // and the rest, notably std::bad_alloc and std::logic_error and such, are reasons to crash
    }
    
    return 0;
}
