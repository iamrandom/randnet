/*
 * buff_pool.h
 *
 *  Created on: 2014-12-17
 *      Author: Random
 */

#ifndef BUFF_POOL_H_
#define BUFF_POOL_H_


#ifdef __cplusplus
#include <cstddef>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct buff_pool;

struct buff_pool*	buff_pool_create(size_t buffer_size, size_t pool_max_cnt);
void	buff_pool_release(struct buff_pool* pool);
void	buff_pool_revive(struct buff_pool* pool, size_t pool_max_cnt);
void*	buff_pool_new_buff(struct buff_pool* pooll, size_t buffer_size);
void	buff_pool_del_buff(struct buff_pool* pool, void* data, size_t buffer_size);
size_t	buff_pool_buffer_size(struct buff_pool* pool);
size_t	buff_pool_max_cnt(struct buff_pool* pool);

#ifdef __cplusplus
}
#endif

#endif /* BUFF_H_ */


