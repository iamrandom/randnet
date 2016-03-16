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
 #define net_thread_sleep(ms) usleep((ms * 1000))
 #endif

#if !defined(ATOMIC_CPP11) && !defined(ATOMIC_C11)

#ifdef __cplusplus
 	#define ATOMIC_CPP11
#else
 	#define ATOMIC_C11
#endif

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

#define net_lock(m)							do{ while(atomic_flag_test_and_set(m)) { net_thread_sleep(0); acquire_memory_fence();}  acquire_memory_fence(); }while(0);
#define net_unlock(m)						do{ release_memory_fence(); atomic_flag_clear((m)); } while(0)


#endif //defined(ATOMIC_CPP11) || defined(ATOMIC_C11)


#endif /* NET_ATOMIC_H_ */

