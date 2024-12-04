#define FILT_MODE_ALLOW
#undef FILT_MODE_ETHERNET
#define FILT_MODE_IPV4
#define FILT_MODE_UDP
#define FILT_MODE_TCP
#define FILT_MODE_CT
#define FUNCNAME xdpfilt_alw_ct

#include "xdpfilt_prog.h"

