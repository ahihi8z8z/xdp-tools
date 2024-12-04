#ifndef COMMON_KERN_USER_H
#define COMMON_KERN_USER_H


#define FEAT_TCP	(1<<0)
#define FEAT_UDP	(1<<1)
#define FEAT_IPV6	(1<<2)
#define FEAT_IPV4	(1<<3)
#define FEAT_ETHERNET	(1<<4)
#define FEAT_CT     (1<<5)
#define FEAT_ALL	(FEAT_TCP|FEAT_UDP|FEAT_IPV6|FEAT_IPV4|FEAT_ETHERNET|FEAT_CT)
#define FEAT_ALLOW	(1<<6)
#define FEAT_DENY	(1<<7)



#define MAP_FLAG_SRC (1<<0)
#define MAP_FLAG_DST (1<<1)
#define MAP_FLAG_TCP (1<<2)
#define MAP_FLAG_UDP (1<<3)
#define MAP_STATE_CT_NEW         (1<<4)
#define MAP_STATE_CT_ESTABLISHED   (1<<5)
#define MAP_FLAGS (MAP_FLAG_SRC|MAP_FLAG_DST|MAP_FLAG_TCP|MAP_FLAG_UDP|MAP_STATE_CT_NEW|MAP_STATE_CT_ESTABLISHED)


// #define MAP_STATE_CT_ALL     (MAP_STATE_CT_NEW|MAP_STATE_CT_ESTABLISH)


#define EAFNOSUPPORT 97
#define EPROTO 71
#define ENONET 64
#define EINVAL 22
#define ENOENT 2

#define COUNTER_SHIFT 8

#define MAP_NAME_PORTS filter_ports
#define MAP_NAME_IPV4 filter_ipv4
#define MAP_NAME_IPV6 filter_ipv6
#define MAP_NAME_ETHERNET filter_ethernet
#define MAP_NAME_CT filter_ct

#include "xdp/xdp_stats_kern_user.h"

#endif
