/* XXX - BSD license */

#ifndef _PORT_IRIX_H
#define _PORT_IRIX_H

#if defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || \
    defined(WITH_IRIX_ARRAY)

void irix_setusercontext(struct passwd *pw);

#endif /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#endif /* ! _PORT_IRIX_H */
