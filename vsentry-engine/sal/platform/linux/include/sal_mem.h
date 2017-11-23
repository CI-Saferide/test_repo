#ifndef __SAL_MEM_H_
#define __SAL_MEM_H_

#define SR_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) calloc(1, (unsigned long)(n)))
#define SR_Free(p) free((caddr_t)p);
#define SR_LOCK pthread_mutex
#define SR_Lock(l) pthread_mutex_lock(l)
#define SR_Unlock(l) pthread_mutex_unlock(l)

#endif
