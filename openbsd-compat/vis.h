#ifndef _BSD_VIS_H
#define	_BSD_VIS_H

#include "config.h"

#ifndef HAVE_VIS

/*
 * to select alternate encoding format
 */
#define	VIS_OCTAL	0x01	/* use octal \ddd format */
#define	VIS_CSTYLE	0x02	/* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#define	VIS_SP		0x04	/* also encode space */
#define	VIS_TAB		0x08	/* also encode tab */
#define	VIS_NL		0x10	/* also encode newline */
#define	VIS_WHITE	(VIS_SP | VIS_TAB | VIS_NL)
#define	VIS_SAFE	0x20	/* only encode "unsafe" characters */

/*
 * other
 */
#define	VIS_NOSLASH	0x40	/* inhibit printing '\' */

char	*vis (char *, int, int, int);
#endif /* HAVE_VIS */

#endif /* _BSD_VIS_H */
