#pragma once
#ifndef __attribute__
#define __attribute__(A)
#endif

#include "..\..\..\log.h"
#include "..\..\..\ssherr.h"
/* Enable the following for verbose logging */
#if (0)
#define debug4 debug2
#define debug5 debug3
#else
#define debug4(a,...)
#define debug5(a,...)
#endif