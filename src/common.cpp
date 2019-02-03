#include "common.hpp"

int port = 12345;
int broadcast_interval = 30;
int timeout = 8 * broadcast_interval;
int alarm_timeout = 9;
bool compress_data = false;
bool real_route_updates = false;
int interlink_netmask = 28;
int interface_association_update_interval = 5;
int arptable_update_interval = 60;
int interface_arptable_update_interval = arptable_update_interval;
std::string secret_key = "s00p3rs3kr3t";
bool stay_in_foreground = false;
int maximum_number_of_route_flush_tries = 10;
bool use_syslog = false;
int minimum_netmask = 24;
struct in_addr min_routable { (172u << 24) + (16u << 16) + (  0u << 8) + (0u << 0) };
struct in_addr max_routable { (172u << 24) + (31u << 16) + (255u << 8) + (0u << 0) };
std::string configfile = "/usr/local/etc/lvrouted.conf";
