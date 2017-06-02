/*
 * buff_pool.c
 *
 *  Created on: 2014-12-17
 *      Author: Random
 */

#include <stdlib.h>
#include "buff_pool.h"
#include "net_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

struct buff_pool
{
	char**						head;
	size_t						buffer_size;
	size_t						pool_cnt;
	size_t						pool_max_cnt;
	net_atomic_flag				flag;
};

struct buff_pool*
buff_pool_create(size_t buffer_size, size_t pool_max_cnt)
{
	struct buff_pool*	pool;
	pool = (struct buff_pool*)malloc(sizeof(struct buff_pool));
	if (!pool)
	{
		return 0;
	}

	pool->head = 0;
	if(pool_max_cnt > 0)
	{
		pool->head = (char**)malloc(sizeof(char*) * pool_max_cnt);
		if(!pool->head)
		{
			free(pool);
			return 0;
		}
	}

	pool->buffer_size = buffer_size;
	pool->pool_cnt = 0;
	pool->pool_max_cnt = pool_max_cnt;
	net_atomic_flag_clear(&pool->flag);
	return pool;
}

void
buff_pool_release(struct buff_pool* pool)
{
	buff_pool_revive(pool, 0);
	free(pool->head);
	free(pool);
}

void
buff_pool_revive(struct buff_pool* pool, size_t pool_max_cnt)
{
	if(!pool) return;
	net_lock(&pool->flag);
	while(pool->pool_cnt > pool_max_cnt)
	{
		--pool->pool_cnt;
		free(pool->head[pool->pool_cnt]);
	}
	pool->pool_max_cnt = pool_max_cnt;
	pool->head = (char**)realloc(pool->head, pool_max_cnt * sizeof(char*));
	net_unlock(&pool->flag);
}

void*
buff_pool_new_buff(struct buff_pool* pool, size_t buffer_size)
{
	void*	data;

	if(!pool || pool->buffer_size != buffer_size)
	{
		return malloc(buffer_size);
	}
	else
	{
		net_lock(&pool->flag);
		if (!pool->pool_cnt)
		{
			net_unlock(&pool->flag);
			return malloc(buffer_size);
		}
		--pool->pool_cnt;
		data = pool->head[pool->pool_cnt];
		net_unlock(&pool->flag);
		return data;
	}
}

void
buff_pool_del_buff(struct buff_pool* pool, void* data, size_t buffer_size)
{
	if(!data) return;

	if(!pool || buffer_size != pool->buffer_size)
	{
		free(data);
		return;
	}
	net_lock(&pool->flag);
	if (pool->pool_cnt >= pool->pool_max_cnt)
	{
		net_unlock(&pool->flag);
		free(data);
		return;
	}
	pool->head[pool->pool_cnt] = (char*)data;
	++pool->pool_cnt;
	net_unlock(&pool->flag);
}

size_t
buff_pool_buffer_size(struct buff_pool* pool)
{
	return pool->buffer_size;
}

size_t
buff_pool_max_cnt(struct buff_pool* pool)
{
	return pool->pool_max_cnt;
}


#ifdef __cplusplus
}
#endif
