/*
 * net_atomic.h
 *
 *  Created on: 2015年10月13日
 *      Author: Random
 */

#ifndef NET_ATOMIC_H_
#define NET_ATOMIC_H_


//#define ATOMIC_CPP11
//#define ATOMIC_C11


#ifdef ATOMIC_CPP11
#include <atomic>
using namespace std;
#define net_atomic_int						atomic<int>
#endif

#ifdef ATOMIC_C11
#include <stdatomic.h>
#define net_atomic_int						atomic_int
#endif

// now noly supper ATOMIC_CPP11 or ATOMIC_C11, gcc 4.9 or g++ 4.7

#if defined(ATOMIC_CPP11) || defined(ATOMIC_C11)

#define NET_ATOMIC_FLAG_INIT				ATOMIC_FLAG_INIT
#define memeory_fence()						atomic_thread_fence(memory_order_seq_cst)
#define release_memory_fence()				atomic_thread_fence(memory_order_release)
#define acquire_memory_fence()				atomic_thread_fence(memory_order_acquire)

#define net_atomic_flag						atomic_flag
#define net_atomic_flag_clear(flag)			atomic_flag_clear((flag))

#define net_try_one_lock(m)					atomic_flag_test_and_set(m)
// #include <stdio.h>
// #define net_lock(m)							while(net_try_one_lock(m)){acquire_memory_fence(); printf("lock %s:%d    %s\n", __FILE__, __LINE__, __FUNCTION__); fflush(stdout);}
// #define net_unlock(m)						atomic_flag_clear((m)); printf("unlock %s:%d    %s\n", __FILE__, __LINE__, __FUNCTION__); fflush(stdout);

#define net_lock(m)							while(net_try_one_lock(m)){acquire_memory_fence();}
#define net_unlock(m)						atomic_flag_clear((m))


#define net_atomic_load(atint)				atomic_load((atint))
#define net_atomic_store(atint, v)			atomic_store((atint), (v))
#define net_atomic_fetch_add(atint, v)		atomic_fetch_add((atint), (v))
#define net_atomic_fetch_sub(atint, v)		atomic_fetch_sub((atint), (v))


#endif //defined(ATOMIC_CPP11) || defined(ATOMIC_C11)




#endif /* NET_ATOMIC_H_ */


