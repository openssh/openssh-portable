#ifndef _ZX_SOCKET_H_
#define _ZX_SOCKET_H_

/*
 * Structure used by kernel to store most
 * addresses.
 */
struct sockaddr {
	__uint8_t    sa_len;		/* total length */
	sa_family_t sa_family;		/* address family */
	char	    sa_data[14];	/* actually longer; address value */
};

#endif
