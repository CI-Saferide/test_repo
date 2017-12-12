#ifndef ENGINE_SAL_H
#define ENGINE_SAL_H

#include "sr_tasks.h"

//CHECK LATER  WHY CANT USE sal_mem.h

#define SR_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) calloc(1, (unsigned long)(n)))
#define SR_Free(p) free((caddr_t)p);

SR_32 sal_rename(const SR_8 *old_filename, const SR_8 *new_filename);

#endif /* ENGINE_SAL_H*/
