SRCS= src/common.cpp src/lvrouted.cpp src/Neighbor.cpp src/Tree.cpp src/Iface.cpp src/MAC.cpp src/Route.cpp
lvrouted: $(SRCS)
	c++ -o lvrouted -std=c++17 $(SRCS) -O2 -fno-rtti -DSVN_VERSION=`svn info . | grep "Last Changed Rev" | sed "s/.*: //g"` -lcrypto
