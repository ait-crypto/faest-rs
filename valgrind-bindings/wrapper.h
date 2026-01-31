#ifndef VALGRIND_WRAPPER_H
#define VALGRIND_WRAPPER_H
#include <stdlib.h>

unsigned long long valgrind_make_mem_undefined(void *_qzz_addr,
                                               size_t _qzz_len);

unsigned long long valgrind_make_mem_defined(void *_qzz_addr,
                                               size_t _qzz_len);

#endif