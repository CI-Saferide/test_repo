#ifndef ENGINE_SAL_H
#define ENGINE_SAL_H

#include "sr_tasks.h"

//TODO: move memory functions BACK to sal_shmem.h

#define SR_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) calloc(1, (unsigned long)(n)))
#define SR_Free(p) free((caddr_t)p);

#define SR_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#define SR_LOCK pthread_mutex_t
#define SR_Lock(l) pthread_mutex_lock(l)
#define SR_Unlock(l) pthread_mutex_unlock(l)

SR_32 sal_rename(const SR_8 *old_filename, const SR_8 *new_filename);

#endif /* ENGINE_SAL_H*/
