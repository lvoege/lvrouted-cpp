#include "Tree.hpp"

#include <cassert>
#include <syslog.h>
#include <queue>
#include <sstream>
#include <arpa/inet.h>
#include <cassert>

void bfs(const Node &node, const std::function<bool (const Node &)> &f) {
    std::queue<const Node *> q;
    q.push(&node);
    while (!q.empty()) {
        auto top = q.front();
        q.pop();
        if (!f(*top))
            break;
        for (auto &c: top->children)
            q.push(&c);
    }
}
static void to_string_helper(std::ostringstream &oss, size_t indent, const std::vector<Node> &nodes) {
    std::string tabs(indent, '\t');
    for (auto &child: nodes) {
        oss << tabs << inet_ntoa({ htonl(child.addr.s_addr) });
        if (child.ethernet)
            oss << " (eth)";
        if (child.gateway)
            oss << " (gw)";
        oss << std::endl;
        to_string_helper(oss, indent + 1, child.children);
    }
}
std::string to_string(const std::vector<Node> &nodes) {
    std::ostringstream oss;
    to_string_helper(oss, 0, nodes);
    return oss.str();
}

std::tuple<Node, RouteSet, in_addr> merge(const std::vector<Node> &trees) {
    Node new_tree;
    new_tree.addr.s_addr = 0;
    new_tree.ethernet = false;
    new_tree.gateway = false;
    new_tree.children.reserve(trees.size());

    struct in_addr_less {
        bool operator()(const in_addr &one, const in_addr &other) const {
            return one.s_addr < other.s_addr;
        }
    };
    std::map<in_addr, std::pair<in_addr, uint8_t>, in_addr_less> routes_with_path_lengths; // address -> gateway + #hops

    struct PriorityQueueElement {
        PriorityQueueElement(uint8_t cost, const Node &node, Node &parent, in_addr gateway) noexcept
                : cost(cost), node(&node), parent(&parent), gateway(gateway) { }
        uint8_t cost;
        const Node *node;
        Node *parent;
        in_addr gateway;
        bool operator<(const PriorityQueueElement &o) const {
            return cost > o.cost;
        }
    };
    std::priority_queue<PriorityQueueElement> todo;
    for (auto &tree: trees) {
        todo.emplace(0, tree, new_tree, tree.addr);
    }
    in_addr default_gateway { 0 };
    while (!todo.empty()) {
        auto em = todo.top();
        todo.pop();
        if (default_gateway.s_addr == 0 && em.node->gateway)
            default_gateway = em.node->addr;
        auto it = routes_with_path_lengths.find(em.node->addr);
        if (it != routes_with_path_lengths.end()) {
            auto &existing_gw = it->second.first;
            auto &existing_cost = it->second.second;
            if (existing_cost == em.cost && existing_gw.s_addr < em.gateway.s_addr)
                existing_gw = em.gateway;
            else if (em.cost < existing_cost) {
                // we've seen this node before yet this one's cost is lower. that can't be.
                throw std::logic_error("Eep!");
            } else {
                // we've seen this node before and this one's cost is higher than what we have. ignore.
            }
        } else {
            // copy this node and hook it into the new tree
            assert(em.node);
            Node new_node;
            new_node.addr = em.node->addr;
            new_node.ethernet = em.node->ethernet;
            new_node.gateway = em.node->gateway;
            new_node.children.reserve(em.node->children.size());
            em.parent->children.push_back(std::move(new_node));
            auto &copy = em.parent->children.back();
            routes_with_path_lengths.emplace(copy.addr, std::make_pair(em.gateway, em.cost));

            /*
             * Create queue elements for the children of this node and push them on. For ethernet
             * links the cost is the parent cost plus 1 else it's the parent cost plus 10. This
             * then strongly prefers paths going over wired connections.
             */
            auto new_cost = em.cost + (em.node->ethernet ? 1 : 10);
            for (auto &child: em.node->children)
                todo.emplace(new_cost, child, copy, em.gateway);
        }
    }

    RouteSet routing_table;
    for (auto &p: routes_with_path_lengths) {
        Route r;
        r.addr = p.first;
        r.netmask = 32;
        r.gateway = p.second.first;
        routing_table.insert(std::move(r));
    }
    
    return { std::move(new_tree), std::move(routing_table), std::move(default_gateway) };
}

/* Store a node into a buffer. It is enough to store the node contents
 * (the address in this case) plus the number of children and recurse.
 * Since the 172.16.0.0/12 range only uses 20 bits, the number of children
 * can be packed into the 12 fixed bits.
 * 
 * It is conceivable for our nodes to have more than 16 addresses to
 * propagate, so packing a node in 24 bits instead of 32 would probably
 * be pushing our luck.
 */
static uint8_t *serialize_rec(const Node &node, uint8_t *buffer, uint8_t *boundary) {
	if (buffer >= boundary)
        throw std::runtime_error("Buffer too small for tree");

	/* put the number of children in the six sixth-to-last bits */
	uint32_t i = node.children.size() << 20;
	/* or in the the "eth" boolean in the upper six bits */
    if (node.ethernet)
        i |= 1 << 26;
    if (node.gateway)
        i |= 1 << 27;
	/* mask out the 20 relevant bits and or the address in */
    i |= node.addr.s_addr & ((1 << 20) - 1);
	/* that's all for this node. store it. */
	*(uint32_t *)buffer = htonl(i);
	buffer += sizeof(int);

    for (auto &child: node.children)
        buffer = serialize_rec(child, buffer, boundary);
    return buffer;
}

size_t serialize(const Node &node, uint8_t *buf, size_t len) {
    return serialize_rec(node, buf, buf + len) - buf;
}

/* This is the converse of tree_to_string_rec(). Unpack the packed-together
 * number of children and node address.
 *
 * NOTE: the upper six bits are reserved and not relevant to this branch of
 * the code. They are explicitly ignored here in order not to trip up if
 * there's anything there.
 */
static Node decode_tree_rec(const uint8_t **pp,
                            const uint8_t *limit) {
    if (*pp > limit - sizeof(int))
        throw std::runtime_error("Faulty packet");
    const uint8_t *p = *pp;
    auto i = ntohl(*(const uint32_t *)p);
    p += sizeof(uint32_t);
    int flags = i >> 26;
    Node n;
    n.addr.s_addr = 0xac100000 + (i & ((1 << 20) - 1));
    n.ethernet = flags & 1;
    n.gateway = flags & 2;
    
    for (i = (i >> 20) & ((1 << 6) - 1); i > 0; i--)
        n.children.push_back(decode_tree_rec(&p, limit));
    *pp = p;
    return n;
}

Node deserialize(const uint8_t *buf, size_t len) {
    auto buf_start = buf;
    auto res = decode_tree_rec(&buf, buf_start + len);
    if (buf != buf_start + len)
        throw std::runtime_error("invalid packet");
    return res;
}
