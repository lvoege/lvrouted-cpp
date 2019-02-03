/* This module defines and implements the tree structure that is passed
   between nodes. It also implements the merging of trees, which is the
   core of the whole routing scheme. */
#ifndef TREE_HPP
#define TREE_HPP

#include <cstddef>
#include <optional>
#include <functional>
#include <vector>

#include "Route.hpp"

struct Node {
    in_addr addr;
    bool ethernet;
    bool gateway;
    std::vector<Node> children;
};

/* For the tree topped by the given node, traverse it breadth-first, calling
   the given function on the nodes. Continue traversing if the function returns
   true. */
void bfs(const Node &, const std::function<bool (const Node &)> &);

std::string to_string(const std::vector<Node> &);

/* Given a list of spanning trees received from neighbors and a set of our
   own addresses, return the spanning tree for this node, plus a routing
   table and a default gateway.
   
   1. Initialize a routing table with routes to our own addresses. This is
      a mapping from address to a pair of cost and gateway.
   2. Reserve a slot to put the default gateway in. This would be the first
      address we see during the tree merge that is indeed marked as a valid
      gateway.
   3. Make a new node to hang the new, merged and pruned tree under.
   4. Traverse the tree breadth-first.  For every node, check if
      there is a route already. If there isn't, add a route and create a new
      node and prepend it to the parent's list of children.

      On the other hand, if there is already a route, check the cost (==
      priority) of that route. If it's less than the cost of the node we're
      looking at, ignore this node and continue traversing because we
      evidently already have a route to the node's address and it's strictly
      better. If it's more than the cost of the current node, panic because
      that shouldn't happen (that's the point of the priority queue after
      all).
      
      If it's equal, have the gateway that has the numerically lowest address
      of the two win. This will keep routes to addresses for which there are
      multiple equally costly paths stable. Also update the default gateway
      if necessary.
   5. From the routing table that maps addresses to pairs of cost and gateway,
      construct one that maps addresses to just the gateway, because the
      caller doesn't care about cost. While doing that, filter out routes that
      are included in a route from the list of directly attached routes. This
      may not be necessary anymore, but it was when route addition didn't work
      correctly.

   Note that the resulting spanning tree is returned as the list of
   first-level nodes, because the top node is relevant only to the
   receiving end. The list of first-level nodes is sent to a neighbor,
   which will create a top node based on the address it received the
   packet from.
*/
std::tuple<Node, RouteSet, in_addr> merge(const std::vector<Node> &);

size_t serialize(const Node &, uint8_t *, size_t);
Node deserialize(const uint8_t *, size_t);

#endif // TREE_HPP
