#include <sys/user.h>

#if defined(__arm__) || defined(__i386__)
#if !defined(PAGE_SIZE)
#error "PAGE_SIZE is not defined"
#endif
#else
#if defined(PAGE_SIZE)
#error "PAGE_SIZE is defined but should not be"
#endif
#endif
