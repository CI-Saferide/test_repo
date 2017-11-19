#ifndef __SAL_OS_H_
#define __SAL_OS_H_

#define SR_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) calloc(1, (unsigned long)(n)))
#define SR_Free(p) free((caddr_t)p);
#define SR_RWLOCK  int // cuurently lock is not needed doe user mode
#define SR_LOCK(x) //(x++)
#define SR_UNLOCK(x) //(x++)

#endif
