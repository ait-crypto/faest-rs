#include "wrapper.h"
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

unsigned long long valgrind_make_mem_undefined(void *_qzz_addr,
                                               size_t _qzz_len) {
  return VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,
                                         VG_USERREQ__MAKE_MEM_UNDEFINED,
                                         (_qzz_addr), (_qzz_len), 0, 0, 0);
}

unsigned long long valgrind_make_mem_defined(void *_qzz_addr, size_t _qzz_len) {
  return VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,
                                         VG_USERREQ__MAKE_MEM_DEFINED,
                                         (_qzz_addr), (_qzz_len), 0, 0, 0);
}