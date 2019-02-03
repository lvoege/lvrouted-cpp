#ifndef ROUTE_HPP
#define ROUTE_HPP

#include "common.hpp"

#include <netinet/in.h>
#include <set>
#include <tuple>

struct Route {
    in_addr addr;
    int netmask;
    in_addr gateway;
};

struct RouteLess {
    bool operator()(const Route &one, const Route &other) const {
        if (one.addr.s_addr < other.addr.s_addr)
            return true;
        if (one.addr.s_addr > other.addr.s_addr)
            return false;
        return one.netmask < other.netmask;
    }
};

using RouteSet = std::set<Route, RouteLess>;

//! Does route a completely include b?
extern bool includes(const Route &a, const Route &b);

//! Does the given addr fall in the given route? *)
extern bool matches(const Route &route, const in_addr &addr);

extern std::string show(const Route &);

extern std::string show(const RouteSet &);

/* Given a list of routes, try to clump together as many routes as possible.

   Take the first route on the todo list:

     If the netmask is the minimum netmask, move the route to the done list
     and recurse.

     If the address is the same as the gateway address and it's a host route,
     drop it. Tree.merge can pass these in the routing table, and this is the
     most convenient place to remove them code-wise.

     Else expand the netmask by one bit. Check if it gobbles up any routes
     to different gateways.
       If so, move the unexpanded route to the done list and recurse.
       If not, remove all routes now covered by the newly expanded route from
         the todo list and recurse.

   Finally, take the now aggregated list of routes and create a set of routes,
   with the addresses of the routes masked according to their netmask.
*/
extern RouteSet aggregate(RouteSet &);

/*  Given a set of old routes and a set of new routes, produce a list
   of routes to delete, a list of routes to add and a list of routes
   that changed their gateway.

   Deletes and adds are easy using set operations. Changes are less
   easy:
     - Build a map from address to route for both the old and the new routes
     - Intersect the old and the new routes. The set type orders on address
       and netmask, so the intersection has all routes for which neither
       address or netmask have changed. These should now be checked to see
       if they've changed gateways.
     - Fold this intersection, building the set of routes that changed
       gateways along the way. For the given route, look up old and new and
       compare the gateway. If different, add to the set, else pass along
       the set unaltered.
*/

extern std::tuple<RouteSet, RouteSet, RouteSet> diff(const RouteSet &old_routes, const RouteSet &new_routes);

/* Commit the given list of adds, deletes and changes to the kernel.
   Attempt a maximum of five extra iterations of checking whether or
   not every change was applied, and redoing those that weren't. */
extern void commit(int routefd, RouteSet deletes, RouteSet adds, RouteSet changed);

/* Return a list of all routes to routable addresses and with a gateway in
   the kernel route table. */
extern RouteSet fetch(int routefd);

/* Try to have the kernel get rid of all gateway routes */
extern void flush(int routefd);

#endif // ROUTE_HPP
