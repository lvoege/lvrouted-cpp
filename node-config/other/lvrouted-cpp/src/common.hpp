#ifndef COMMON_HPP
#define COMMON_HPP

#include <map>
#include <string>
#include <netinet/in.h>
#include <unistd.h>
#include <set>
#include <stdexcept>

extern int port;
extern int broadcast_interval;
extern int timeout;
extern int alarm_timeout;
extern bool compress_data;
extern bool real_route_updates;
extern int interlink_netmask;
extern int interface_association_update_interval;
extern int arptable_update_interval;
extern int interface_arptable_update_interval;
extern std::string secret_key;
extern bool stay_in_foreground;
extern int maximum_number_of_route_flush_tries;
extern bool use_syslog;
extern int minimum_netmask;
extern struct in_addr min_routable, max_routable;
extern std::string configfile;

struct InAddrLess {
    bool operator()(const struct in_addr &one, const struct in_addr &other) const {
        return one.s_addr < other.s_addr;
    }
};

static inline bool addr_in_range(in_addr_t &a) {
    return a >= min_routable.s_addr && a <= max_routable.s_addr;
}

template<typename T>
using InAddrMap = std::map<struct in_addr, T, InAddrLess>;
using InAddrSet = std::set<struct in_addr, InAddrLess>;

struct FileDescriptor {
    FileDescriptor(int fd): fd(fd) { }
    ~FileDescriptor() {
        if (fd != -1)
            close(fd);
    }
    int fd;
};

#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

inline constexpr bool is_nanostation(const uint8_t bytes[6]) {
    return (bytes[0] == 0x00 && bytes[1] == 0x15 && bytes[2] == 0x6d) ||
           (bytes[0] == 0x00 && bytes[1] == 0x27 && bytes[2] == 0x22);
}

inline constexpr in_addr_t bitmask(int masklen) {
    switch (masklen) {
    case 0: return 0;
    case 1: return 0b10000000000000000000000000000000;
    case 2: return 0b11000000000000000000000000000000;
    case 3: return 0b11100000000000000000000000000000;
    case 4: return 0b11110000000000000000000000000000;
    case 5: return 0b11111000000000000000000000000000;
    case 6: return 0b11111100000000000000000000000000;
    case 7: return 0b11111110000000000000000000000000;
    case 8: return 0b11111111000000000000000000000000;
    case 9: return 0b11111111100000000000000000000000;
    case 10: return 0b11111111110000000000000000000000;
    case 11: return 0b11111111111000000000000000000000;
    case 12: return 0b11111111111100000000000000000000;
    case 13: return 0b11111111111110000000000000000000;
    case 14: return 0b11111111111111000000000000000000;
    case 15: return 0b11111111111111100000000000000000;
    case 16: return 0b11111111111111110000000000000000;
    case 17: return 0b11111111111111111000000000000000;
    case 18: return 0b11111111111111111100000000000000;
    case 19: return 0b11111111111111111110000000000000;
    case 20: return 0b11111111111111111111000000000000;
    case 21: return 0b11111111111111111111100000000000;
    case 22: return 0b11111111111111111111110000000000;
    case 23: return 0b11111111111111111111111000000000;
    case 24: return 0b11111111111111111111111100000000;
    case 25: return 0b11111111111111111111111110000000;
    case 26: return 0b11111111111111111111111111000000;
    case 27: return 0b11111111111111111111111111100000;
    case 28: return 0b11111111111111111111111111110000;
    case 29: return 0b11111111111111111111111111111000;
    case 30: return 0b11111111111111111111111111111100;
    case 31: return 0b11111111111111111111111111111110;
    case 32: return 0b11111111111111111111111111111111;
    default: throw std::domain_error(std::string("Invalid netmask: ") + std::to_string(masklen));
    }
}
 
#endif // COMMON_HPP
