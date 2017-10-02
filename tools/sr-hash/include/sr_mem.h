#ifndef __SR_MEM__H_
#define __SR_MEM__H_

#ifdef __KERNEL__
#define SR_Malloc(p, t, n) (p = (t) SR_ALLOC((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) SR_ZALLOC((unsigned long)(n)))
#define SR_Free(p) SR_FREE((caddr_t)p);
#else
#define SR_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) calloc(1, (unsigned long)(n)))
#define SR_Free(p) free((caddr_t)p);
#endif

#endif
