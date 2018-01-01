#ifndef __SAL_MEM_H_
#define __SAL_MEM_H_

#define SR_Zalloc(p, t, n) (p = (t) kcalloc(1, (unsigned long)(n), GFP_KERNEL))
#define SR_Free(p) kfree((caddr_t)p);

#endif
