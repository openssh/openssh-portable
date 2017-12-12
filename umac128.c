/* $OpenBSD: umac128.c,v 1.1 2017/12/12 15:06:12 naddy Exp $ */

#define UMAC_OUTPUT_LEN	16
#define umac_new	umac128_new
#define umac_update	umac128_update
#define umac_final	umac128_final
#define umac_delete	umac128_delete

#include "umac.c"
