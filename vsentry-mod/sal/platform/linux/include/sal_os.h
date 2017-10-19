#ifndef __SAL_OS_H_
#define __SAL_OS_H_

#define SR_Malloc(p, t, n) (p = (t) SR_ALLOC((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) SR_ZALLOC((unsigned long)(n)))
#define SR_Free(p) SR_FREE((caddr_t)p);
#define SR_RWLOCK       rwlock_t
#define SR_LOCK(x) //(x++)
#define SR_UNLOCK(x) //(x++)

#endif
