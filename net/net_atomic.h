/*
 * net_atomic.h
 *
 *  Created on: 2015年10月13日
 *      Author: Random
 */

#ifndef NET_ATOMIC_H_
#define NET_ATOMIC_H_

#if defined(WIN32) || defined(_WIN32_WINNT)
#define NET_WIN
#endif

#ifdef __linux
#define NET_LINUX
#endif

 #ifdef NET_WIN
 #ifndef __CYGWIN__
 #define __CYGWIN__
 #endif
 #include <windows.h>
 #define net_thread_sleep(ms)  Sleep(ms);
 #endif

 #ifdef NET_LINUX
 #include <unistd.h>
#include <time.h>
 // #define net_thread_sleep(ms) usleep((ms * 1000))
 #define net_thread_sleep(ms)  {struct timespec ts; ts.tv_sec= ((ms)/1000); ts.tv_nsec=((ms)%1000) * 1000000; nanosleep(&ts, 0);}
 #endif

#if !defined(ATOMIC_CPP11) && !defined(ATOMIC_C11)
#  ifdef __cplusplus
#    if __cplusplus >= 201103L // c++ 11
#      define ATOMIC_CPP11
#    endif
#  else
#    if __STDC_VERSION__ >= 201112L  // c11
#      define ATOMIC_C11
#    endif
#  endif
#endif

#ifdef ATOMIC_CPP11
#include <atomic>
using namespace std;
#endif

#ifdef ATOMIC_C11
#include <stdatomic.h>
#endif


// now only supper ATOMIC_CPP11 or ATOMIC_C11, gcc 4.9 or g++ 4.7, also vs2013
#if defined(ATOMIC_CPP11) || defined(ATOMIC_C11)

#define NET_ATOMIC_FLAG_INIT				ATOMIC_FLAG_INIT
#define memeory_fence()						atomic_thread_fence(memory_order_seq_cst)
#define release_memory_fence()				atomic_thread_fence(memory_order_release)
#define acquire_memory_fence()				atomic_thread_fence(memory_order_acquire)

#define net_atomic_flag						atomic_flag
#define net_atomic_flag_clear(m)			atomic_flag_clear((m))

#define net_lock(m)							while(atomic_flag_test_and_set_explicit((m), memory_order_acquire)) { net_thread_sleep(0); }

#define net_unlock(m)						atomic_flag_clear_explicit((m), memory_order_release)

#endif //defined(ATOMIC_CPP11) || defined(ATOMIC_C11)


#endif /* NET_ATOMIC_H_ */

