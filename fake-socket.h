#ifndef _FAKE_SOCKET_H
#define _FAKE_SOCKET_H

#include "config.h"
#include "sys/types.h"

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
# define	_SS_MAXSIZE	128	/* Implementation specific max size */
# define	_SS_ALIGNSIZE	(sizeof(int))
# define	_SS_PAD1SIZE	(_SS_ALIGNSIZE - sizeof(u_short))
# define	_SS_PAD2SIZE	(_SS_MAXSIZE - (sizeof(u_short) + \
					_SS_PAD1SIZE + _SS_ALIGNSIZE))

struct sockaddr_storage {
  u_short	ss_family;
  char		__ss_pad1[_SS_PAD1SIZE];
  int			__ss_align;
  char		__ss_pad2[_SS_PAD2SIZE];
};
#endif /* !HAVE_STRUCT_SOCKADDR_STORAGE */

#ifndef IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *) (a))[0] == 0 && ((u_int32_t *) (a))[1] == 0 && \
	 ((u_int32_t *) (a))[2] == 0 && ((u_int32_t *) (a))[3] == htonl (1))
#endif /* !IN6_IS_ADDR_LOOPBACK */

#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr {
	u_int8_t		s6_addr[16];
};
#endif /* !HAVE_STRUCT_IN6_ADDR */

#ifndef HAVE_STRUCT_SOCKADDR_IN6
struct sockaddr_in6 {
   unsigned short sin6_family;
	u_int16_t sin6_port;
	u_int32_t sin6_flowinfo;
	struct in6_addr sin6_addr;
};
#endif /* !HAVE_STRUCT_SOCKADDR_IN6 */

#ifndef AF_INET6
/* Define it to something that should never appear */
#define AF_INET6 AF_MAX
#endif

#endif /* !_FAKE_SOCKET_H */

