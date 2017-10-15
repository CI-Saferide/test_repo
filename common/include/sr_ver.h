#ifndef __SR_VER__
#define __SR_VER__

#include "sr_build_ver.h"

#define KERNEL_MODULE_VER_MAJOR			0
#define KERNEL_MODULE_VER_MINOR			1
#define KERNEL_MODULE_VER_BUILD			SR_GIT_BUILD

#define ENGINE_VER_MAJOR				KERNEL_MODULE_VER_MAJOR  /* currently same version */
#define ENGINE_VER_MINOR				KERNEL_MODULE_VER_MINOR  /* currently same version */
#define ENGINE_VER_BUILD				KERNEL_MODULE_VER_BUILD  /* currently same version */

#endif /*__SR_VER__ */
