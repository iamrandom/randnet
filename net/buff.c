/*
 * buff.c
 *
 *  Created on: 2014-12-17
 *      Author: Random
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "net_atomic.h"
#include "buff.h"

#ifdef __cplusplus
extern "C" {
#endif

unsigned int
buff_get_space(unsigned short pool_cnt, unsigned short buffer_size,
	unsigned int uHRead, unsigned int uLRead, unsigned int uHWrite, unsigned int uLWrite)
{
	if(uHRead > uHWrite)
	{
		return (uHRead - uHWrite) * buffer_size + uLRead - uLWrite;
	}
	if(uHRead == uHWrite)
	{
		assert(uLWrite <= uLRead);
		return uLRead - uLWrite;
	}
	return (2 * pool_cnt + uHRead - uHWrite) * buffer_size + uLRead - uLWrite;
}

int
buff_gc_help(void** buffers, unsigned int pool_cnt, unsigned int buffer_size, unsigned short* pfreeH,
	unsigned int uHRead, unsigned int uHWrite, struct buff_pool* pool )
{
	unsigned int uHFree;
	int cnt;

	cnt = 0;
	uHFree = *pfreeH;
	while(uHFree != uHRead)
	{
		if((uHFree % pool_cnt) == uHWrite % pool_cnt)
		{
			uHFree = (uHFree + 1) % (2 * pool_cnt);
			continue;
		}
		if(buffers[uHFree % pool_cnt])
		{
			buff_pool_del_buff(pool, buffers[uHFree % pool_cnt], buffer_size);
			buffers[uHFree % pool_cnt] = 0;
			++cnt;
		}
		uHFree = (uHFree + 1) % (2 * pool_cnt);
	}

	*pfreeH = (unsigned short)uHFree;
	return cnt;
}


#include "net_atomic.h"

typedef void(*recv_release_fun)(struct recv_buff*);
typedef size_t(*recv_prepare_fun)(struct recv_buff*, void** pdata);
typedef int(*recv_consume_fun)(struct recv_buff*, size_t usize);
typedef int(*recv_read_fun)(struct recv_buff*, void* buff, int usize);

struct recv_buff
{
	void**					buffers;
	int*					lens;		//only in vB
	volatile unsigned int	write;
	volatile unsigned int	read;
	unsigned short			buffer_size; //only in vB
	unsigned short			pool_cnt;
	unsigned short			freeH;
	enum EnByteSize			en_byte;
	net_atomic_flag			prep_flag;
	struct buff_pool*		pool;

	unsigned int			check;		// check for a msg in vA, and a msg recv len in vB

	//diff version fun
	recv_release_fun		release_fun;
	recv_prepare_fun		prepare_fun;
	recv_consume_fun		consume_fun;
	recv_read_fun			read_fun;
};



struct recv_buff*
recv_buff_create_vA(enum EnByteSize en_byte, unsigned short pool_cnt, struct buff_pool* pool)
{
	struct recv_buff* buff;

	assert(pool_cnt <= 0xefffu);
	buff = (struct recv_buff*)malloc(sizeof(struct recv_buff));
	if(!buff)
	{
		return 0;
	}
	buff->buffers = (void**)malloc(pool_cnt * sizeof(void*));
	if(!buff->buffers)
	{
		free(buff);
		return 0;
	}
	memset(buff->buffers, 0, sizeof(void*) * pool_cnt);
	buff->freeH = pool_cnt;
	buff->write = 0;
	buff->read = ((unsigned int)pool_cnt) << 16;
	buff->en_byte = en_byte;
	buff->pool_cnt = pool_cnt;
	buff->buffer_size = (unsigned short)buff_pool_buffer_size(pool);
	buff->pool = pool;
	buff->check = ((unsigned int)pool_cnt) << 16;
	net_atomic_flag_clear(&buff->prep_flag);
	memeory_fence();
	return buff;
}

void
recv_buff_release_vA(struct recv_buff* rbuff)
{
	unsigned short i;
	acquire_memory_fence();
	if(!rbuff) return;	
	for(i = 0; i < rbuff->pool_cnt; ++i)
	{
		if(!rbuff->buffers[i]) continue;		
		buff_pool_del_buff(rbuff->pool, rbuff->buffers[i], rbuff->buffer_size);
	}
	free(rbuff->buffers);
	free(rbuff);
	release_memory_fence();
}


char
recv_buff_is_full_vA(struct recv_buff* rbuff)
{
	return rbuff->write == rbuff->read;
}

size_t
recv_buff_prepare_vA(struct recv_buff* rbuff, void** pdata)
{

	unsigned int uRead;
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uLWrite;
	unsigned int uHRead;
	unsigned int uLRead;
	unsigned int uSpace;
	size_t size;
	void* pbuffer;

	size = 0;

	acquire_memory_fence();
	uRead = rbuff->read;
	uWrite = rbuff->write;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;
	

	uSpace = buff_get_space(rbuff->pool_cnt, rbuff->buffer_size, uHRead, uLRead, uHWrite, uLWrite);
	assert(uSpace <= (rbuff->pool_cnt * (unsigned int)rbuff->buffer_size));
	if(uSpace == 0) 
	{
		*pdata = 0;
		return 0;
	}
	pbuffer = rbuff->buffers[uHWrite % rbuff->pool_cnt];
	if(!pbuffer)
	{
		pbuffer = buff_pool_new_buff(rbuff->pool, rbuff->buffer_size);
		if(!pbuffer)
		{
			*pdata = 0;
			return 0;
		}
		rbuff->buffers[uHWrite % rbuff->pool_cnt] = pbuffer;
	}
	if(uHRead == uHWrite)
	{
		size = uSpace;
	}
	else
	{
		size = (size_t)rbuff->buffer_size - uLWrite;
	}
	if(size > 0)
	{
		*pdata = (char*)pbuffer + uLWrite;
	}
	else
	{
		*pdata = 0;
		return 0;
	}
	if(size > 0)
	{
		net_lock(&rbuff->prep_flag);
	}
	release_memory_fence();
	return size;
}



int
buff_gain_msg_size(void** buffers, enum EnByteSize en_byte, unsigned short pool_cnt, unsigned short buffer_size,
	unsigned int uHRead, unsigned int uLRead, unsigned int uHWrite, unsigned int uLWrite)
{
	unsigned int write_size;
	unsigned int uNextH;
	unsigned int uNextL;
	unsigned int uMsgSize;
	unsigned short i;
	unsigned char uc;

	uMsgSize = 0;
	write_size = (unsigned int)pool_cnt * buffer_size - buff_get_space(pool_cnt, buffer_size, uHRead, uLRead, uHWrite, uLWrite);
	if (write_size < (unsigned int)en_byte)
	{
		return 0;
	}
	for(i = 0; i < en_byte; ++i)
	{
		uNextH = (uHRead + (uLRead + i) / buffer_size) % pool_cnt;
		uNextL = (uLRead + i) % buffer_size;
		memcpy(&uc, ((char**)buffers)[uNextH] + uNextL, 1);
		uMsgSize |= ((unsigned int)uc) << (i * 8);
	}
	if (uMsgSize < (unsigned int)en_byte)
	{

		return enErr_Recv_MsgSmall;
	}
	if(uMsgSize > (unsigned int)pool_cnt * buffer_size)
	{
		return enErr_Recv_MsgBig;
	}
	if(uMsgSize > write_size)
	{
	
		return 0;
	}
	return (int)uMsgSize;
}

int
recv_buff_check_new_msg(struct recv_buff* rbuff, unsigned int uWrite)
{
	unsigned int uHWrite;
	unsigned int uLWrite;
	unsigned int uHRead;
	unsigned int uLRead;
	int err;
	int count;

	count = 0;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = rbuff->check >> 16;
	uLRead = (rbuff->check << 16) >> 16;
	for( ; ; )
	{
		err = buff_gain_msg_size(rbuff->buffers, rbuff->en_byte, rbuff->pool_cnt, rbuff->buffer_size, 
			uHRead, uLRead, uHWrite, uLWrite);
		if(err < 0)
		{
			return err;
		}
		if(err == 0)
		{
			return count;
		}
		uLRead += err;
		uHRead = (uHRead + uLRead / rbuff->buffer_size) % (2 * rbuff->pool_cnt);
		uLRead %= rbuff->buffer_size;
		rbuff->check = (uHRead << 16) | uLRead;
		++count;
	}
	return count;
}

int
recv_buff_consume_vA(struct recv_buff* rbuff, size_t usize)
{
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uLWrite;
	int ret;
	
	assert(usize <= rbuff->buffer_size * (size_t)rbuff->pool_cnt);
	if(usize == 0) {
		net_unlock(&rbuff->prep_flag);
		return 0;
	}
	uWrite = rbuff->write;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uLWrite += (unsigned int)usize;
	uHWrite = (uHWrite + uLWrite/rbuff->buffer_size) % (2 * rbuff->pool_cnt);
	uLWrite %= rbuff->buffer_size;
	uWrite = uHWrite << 16 | uLWrite;

	// check msg
	ret = recv_buff_check_new_msg(rbuff, uWrite);
	release_memory_fence();
	// must keep check before set write value. Or the gc will release the write buffer before check without lock
	rbuff->write = uWrite;
	net_unlock(&rbuff->prep_flag);
	return ret;
}


int
recv_buff_read_vA(struct recv_buff* rbuff, void* buff, int usize)
{

	unsigned int uRead;
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uLWrite;
	unsigned int uHRead;
	unsigned int uLRead;
	unsigned int msg_size;
	unsigned int cur_buffer_size;
	unsigned int pool_cnt;
	unsigned int buffer_size;
	
	int err;
	void* pMsg, *pData;
	unsigned int i, uH, uL;

//	buff_lock(&rbuff->flag);
	acquire_memory_fence();

	uRead = rbuff->read;
	uWrite = rbuff->write;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;
	pool_cnt = rbuff->pool_cnt;
	buffer_size = rbuff->buffer_size;

	err = buff_gain_msg_size(rbuff->buffers, rbuff->en_byte, pool_cnt, buffer_size, 
		uHRead, uLRead, uHWrite, uLWrite);
	if(err <= 0)
	{
//		buff_unlock(&rbuff->flag);
		return err;
	}
	msg_size = err;
	if ((unsigned int)usize < (msg_size - (unsigned int)rbuff->en_byte))
	{
//		buff_unlock(&rbuff->flag);
		return msg_size - rbuff->en_byte;
	}
	assert(uLRead <= buffer_size);

	uLRead += rbuff->en_byte;
	uHRead = (uHRead + uLRead / buffer_size) % ( 2 * pool_cnt);
	uLRead %= buffer_size;
	msg_size -= rbuff->en_byte;

	cur_buffer_size = buffer_size - uLRead;
	if(cur_buffer_size >= msg_size)
	{

		pMsg = ((char**)rbuff->buffers)[uHRead % pool_cnt] + uLRead;
		uLRead += msg_size;
		uHRead = (uHRead + uLRead / buffer_size) % ( 2 * pool_cnt);
		uLRead %= buffer_size;
		memcpy(buff, pMsg , (size_t)msg_size);
	}
	else
	{
		pMsg = buff;
		if(!pMsg)
		{
			return enErr_NoMemory;
		}
		pData = ((char**)rbuff->buffers)[uHRead % pool_cnt] + uLRead;
		memcpy(pMsg, pData, cur_buffer_size);

		uH = (msg_size - cur_buffer_size) / buffer_size;
		uL = (msg_size - cur_buffer_size) % buffer_size;
		for(i = 0; i < uH; ++i)
		{
			memcpy((char*)pMsg + cur_buffer_size, rbuff->buffers[(uHRead + i + 1) % pool_cnt], buffer_size);
			cur_buffer_size += buffer_size;
		}
		memcpy((char*)pMsg + cur_buffer_size, rbuff->buffers[((uHRead + uH + 1) % pool_cnt)], uL);
		uHRead = (uHRead + uH + 1) % (2 * pool_cnt);
		uLRead = uL;
	}

	buff_gc_help(rbuff->buffers, rbuff->pool_cnt, rbuff->buffer_size, 
		&rbuff->freeH, uHRead, uHWrite, rbuff->pool);

	release_memory_fence();
	rbuff->read = (uHRead << 16) | uLRead;

//	buff_unlock(&rbuff->flag);
	return (int)msg_size;
}


struct recv_buff*
recv_buff_create_vB(enum EnByteSize en_byte, uint16_t pool_cnt, struct buff_pool* pool)
{
	struct recv_buff* queue;

	assert(pool_cnt <= 0xefffu);
	queue = (struct recv_buff*)malloc(sizeof(struct recv_buff));
	if(!queue)
	{
		return 0;
	}

	queue->buffers = (void**)malloc(pool_cnt * sizeof(void*));
	if(!queue->buffers)
	{
		free(queue);
		return 0;
	}
	queue->lens = (int*)malloc(pool_cnt * sizeof(int));
	if(!queue->lens)
	{
		free(queue->buffers);
		free(queue);
		return 0;
	}
	memset(queue->buffers, 0, sizeof(void*) * pool_cnt);
	queue->freeH = pool_cnt;
	queue->write = 0;
	queue->read = ((unsigned int)pool_cnt);
	queue->en_byte = en_byte;
	queue->pool_cnt = pool_cnt;
	queue->pool = pool;
	queue->check = 0;
	net_atomic_flag_clear(&queue->prep_flag);
	memeory_fence();
	return queue;
}



void
recv_buff_release_vB(struct recv_buff* rbuff)
{
	unsigned short i;
	acquire_memory_fence();
	if(!rbuff) return;	
	for(i = 0; i < rbuff->pool_cnt; ++i)
	{
		if(!rbuff->buffers[i]) continue;	
		buff_pool_del_buff(rbuff->pool, rbuff->buffers[i], (size_t)rbuff->lens[i]);
	}
	free(rbuff->buffers);
	free(rbuff->lens);
	free(rbuff);
	release_memory_fence();
}


size_t
recv_buff_prepare_vB(struct recv_buff* rbuff, void** pdata)
{
	unsigned int uWrite;
	unsigned int uRead;
	unsigned int check;
	unsigned int curWrite;
	int msg_size;
	char* pc;

	if(!rbuff) return 0;
	acquire_memory_fence();
	uWrite = rbuff->write;
	uRead = rbuff->read;
	check = rbuff->check;
	// is full?
	if(uWrite == uRead) return 0;
	curWrite = uWrite % rbuff->pool_cnt;
	if(check < (unsigned int)rbuff->en_byte)
	{
		// read a msg size
		pc = (char*)(rbuff->lens + curWrite);
		*pdata = (void*)(pc + check);
		return  (unsigned int)rbuff->en_byte - check;
	}
	else
	{
		// read a msg
		msg_size = rbuff->lens[curWrite];
		if (msg_size <= 0) return 0;
		pc = (char*)rbuff->buffers[curWrite] + (check - (unsigned int)rbuff->en_byte);
		*pdata = (void*)pc;
		return (unsigned int)msg_size - (check - (unsigned int)rbuff->en_byte);
	}
	return 0;
}



int
recv_buff_consume_vB(struct recv_buff* rbuff, size_t usize)
{
	unsigned int uWrite;
	unsigned int check;
	unsigned int curWrite;
	unsigned int en_byte;
	unsigned int msg_size;
	unsigned char* pc;
	void* msg_buff;
	unsigned int i;
	
	if(!rbuff || !usize) return 0;
	acquire_memory_fence();
	uWrite = rbuff->write;
	check = rbuff->check;
	en_byte = (unsigned int)rbuff->en_byte;
	curWrite = uWrite % rbuff->pool_cnt;
	
	
	if(check < en_byte)
	{
		if( (check + usize) > en_byte )
		{
			return -1;
		}
		check += usize;
		if(check == en_byte)
		{
			// comp the msg length
			pc = (unsigned char*)(rbuff->lens + curWrite);
			msg_size = 0;
			for(i = 0; i < en_byte; ++i)
			{
				msg_size |= (pc[i]) << (i * 8);
			}

			if(((int)msg_size) < 0)
			{
				return enErr_Recv_MsgBig;
			}
			if(msg_size < en_byte)
			{
				return enErr_Recv_MsgSmall;
			}
			msg_size = msg_size - en_byte;
			rbuff->lens[curWrite] = (int)msg_size;
			msg_buff = buff_pool_new_buff(rbuff->pool, msg_size);
			if(!msg_buff)
			{
				return enErr_NoMemory;
			}
			rbuff->buffers[curWrite] = msg_buff;
		}
		rbuff->check = check;
	}
	else
	{
		msg_size = (unsigned int)rbuff->lens[curWrite];
		
		if(msg_size < (check - en_byte + usize ) )
		{
			return enErr_Recv_MsgBig;
		}
		check += usize;
		rbuff->check = check;
		if((check - en_byte) == msg_size)
		{
			// a msg ok
			uWrite = (uWrite + 1) % (2 * rbuff->pool_cnt);
			rbuff->check = 0;
			release_memory_fence();
			rbuff->write = uWrite;
			return 1;
		}



		rbuff->check = check;
	}
	return 0;
}

int
recv_buff_read_vB(struct recv_buff* rbuff, void* buff, int usize)
{
	int msg_len;
	unsigned int uRead;
	unsigned int uHeight;

	if(!rbuff || !buff || ((size_t)usize != sizeof(void*))) return 0;
	acquire_memory_fence();
	uRead = rbuff->read;
	uHeight = (rbuff->write + rbuff->pool_cnt) % (2 * rbuff->pool_cnt);

	if (uHeight == uRead)
	{
		// no message
		return 0;
	}
	*((void**)buff) = rbuff->buffers[uRead % rbuff->pool_cnt];
	msg_len = rbuff->lens[uRead % rbuff->pool_cnt];

	rbuff->lens[uRead % rbuff->pool_cnt] = 0;
	rbuff->buffers[uRead % rbuff->pool_cnt] = 0;

	uRead = (uRead + 1) % (2 * rbuff->pool_cnt);	

	release_memory_fence();
	rbuff->read = uRead;

	return msg_len;
}

struct recv_buff*	
recv_buff_create(enum EnByteSize en_byte, uint16_t pool_cnt, struct buff_pool* pool, int Version)
{
	struct recv_buff* rbuff;
	switch(Version)
	{

	case RECV_BUFF_USE_QUEUE:
		rbuff = recv_buff_create_vB(en_byte, pool_cnt, pool);
		if(rbuff)
		{
			rbuff->release_fun = recv_buff_release_vB;
			rbuff->prepare_fun = recv_buff_prepare_vB;
			rbuff->consume_fun = recv_buff_consume_vB;
			rbuff->read_fun = recv_buff_read_vB;
		}
		break;
	case RECV_BUFF_USE_BUFF:
	default:
		rbuff = recv_buff_create_vA(en_byte, pool_cnt, pool);
		if(rbuff)
		{
			rbuff->release_fun = recv_buff_release_vA;
			rbuff->prepare_fun = recv_buff_prepare_vA;
			rbuff->consume_fun = recv_buff_consume_vA;
			rbuff->read_fun = recv_buff_read_vA;
		}
		break;
	}
	return rbuff;
}

void				
recv_buff_release(struct recv_buff* rbuff)
{
	return rbuff->release_fun(rbuff);
}

size_t				
recv_buff_prepare(struct recv_buff* rbuff, void** pdata)
{
	return rbuff->prepare_fun(rbuff, pdata);
}

int					
recv_buff_consume(struct recv_buff* rbuff, size_t usize)
{
	return rbuff->consume_fun(rbuff, usize);
}

int					
recv_buff_read(struct recv_buff* rbuff, void* buff, int usize)
{
	return rbuff->read_fun(rbuff, buff, usize);
}





struct send_buff
{
	void**					buffers;
	volatile unsigned int	write;
	volatile unsigned int	read;
	unsigned short			buffer_size;
	unsigned short			pool_cnt;
	unsigned short			freeH;
	enum EnByteSize			en_byte;
//	atomic_flag				flag;
	struct buff_pool*		pool;
};

struct send_buff*
send_buff_create(enum EnByteSize en_byte, unsigned short pool_cnt, struct buff_pool* pool)
{
	struct send_buff* sbuff;
	assert(pool_cnt <= 0xefffu);
	sbuff = (struct send_buff*)malloc(sizeof(struct send_buff));
	if(!sbuff)
	{
		return 0;
	}
	sbuff->buffers = (void**)malloc(sizeof(void*) * pool_cnt);
	if(!sbuff->buffers)
	{
		free(sbuff);
		return 0;
	}
	memset(sbuff->buffers, 0, sizeof(void*) * pool_cnt);
	sbuff->freeH = pool_cnt;
	sbuff->write = 0;
	sbuff->read = ((unsigned int)pool_cnt) << 16;
	sbuff->en_byte = en_byte;
	sbuff->pool_cnt = pool_cnt;
	sbuff->buffer_size = (unsigned short)buff_pool_buffer_size(pool);
	sbuff->pool = pool;

//	buff_flag_init(&sbuff->flag);
	memeory_fence();
	return sbuff;
}

void
send_buff_release(struct send_buff* sbuff)
{
	unsigned short i;
	acquire_memory_fence();
	if(!sbuff) return;	
	for(i = 0; i < sbuff->pool_cnt; ++i)
	{
		if(!sbuff->buffers[i]) continue;
		buff_pool_del_buff(sbuff->pool, sbuff->buffers[i], sbuff->buffer_size);
		sbuff->buffers[i] = 0;
	}
	free(sbuff->buffers);
	free(sbuff);
	release_memory_fence();
}

size_t
send_buff_prepare(struct send_buff* sbuff, void** pdata)
{
	unsigned int uRead;
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uLWrite;
	unsigned int uHRead;
	unsigned int uLRead;
	unsigned int uHW, uHR, uSpace;

	acquire_memory_fence();
	uRead = sbuff->read;
	uWrite = sbuff->write;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;

	uHW = uHWrite % sbuff->pool_cnt;
	uHR = uHRead % sbuff->pool_cnt;

	if((uHRead != uHWrite) && (uHW == uHR))
	{
		
		assert(uLWrite >= uLRead);
		uSpace = uLWrite - uLRead;
	}
	else
	{
		uSpace = sbuff->buffer_size - uLRead;
	}
	assert(uSpace <= sbuff->buffer_size);

	if(uSpace == 0)
	{
		*pdata = 0;
	}
	else
	{
		*pdata = ((char**)sbuff->buffers)[uHR] + uLRead;
	}
	return uSpace;
}

void
send_buff_consume(struct send_buff* sbuff, size_t usize)
{
	unsigned int uRead;
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uHRead;
	unsigned int uLRead;


	assert(usize <= (unsigned int)sbuff->buffer_size * sbuff->pool_cnt);
	if(usize == 0)
	{
		return;
	}
	acquire_memory_fence();
	uWrite = sbuff->write;
	uRead = sbuff->read;

	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;
	uLRead += (unsigned int)usize;
	uHRead = (uHRead + uLRead / sbuff->buffer_size) % (2 * sbuff->pool_cnt);
	uLRead %= sbuff->buffer_size;

	uHWrite = uWrite >> 16;


	buff_gc_help(sbuff->buffers, sbuff->pool_cnt, sbuff->buffer_size, 
		&sbuff->freeH, uHRead, uHWrite, sbuff->pool);


	release_memory_fence();
	sbuff->read = uHRead << 16 | uLRead;
}

#include <stdio.h>
int
send_buff_write(struct send_buff* sbuff, const void* pdata, int size)
{
	unsigned int uRead;
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uLWrite;
	unsigned int uHRead;
	unsigned int uLRead;
	unsigned int uSpace;
	unsigned int msg_size;
	unsigned int pool_cnt, buffer_size;
	void**	buffers;
	void* bf;
	unsigned int uCurRestSize, uNextH;
	unsigned int i, uH, uL;
	unsigned char uc;
	struct buff_pool*	pool;
	unsigned int usize;

	if(size < 0) return 0;
	usize = size;
	i = sbuff->en_byte;
	while( i > 0)
	{
		usize >>= 8;
		--i;
	}
	if(usize > 0) return 0;

	usize = size;
	bf = 0;

	pool = sbuff->pool;

//	buff_lock(&sbuff->flag);
	acquire_memory_fence();
	uRead = sbuff->read;
	uWrite = sbuff->write;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;
	msg_size = (unsigned int)usize + sbuff->en_byte;
	pool_cnt = sbuff->pool_cnt;
	buffer_size = sbuff->buffer_size;
	buffers = sbuff->buffers;

	uSpace = buff_get_space(pool_cnt, buffer_size, uHRead, uLRead, uHWrite, uLWrite);
	assert(uSpace <= pool_cnt * buffer_size);
	if(uSpace < msg_size)
	{
//		buff_unlock(&sbuff->flag);
		return 0;
	}
	// write size
	for (i = 0; i < (unsigned int)sbuff->en_byte; ++i)
	{
		if(!buffers[uHWrite % pool_cnt])
		{
			bf = buff_pool_new_buff(pool, buffer_size);
			if(!bf)
			{
				return enErr_NoMemory;
			}			
			buffers[uHWrite % pool_cnt] = bf;
		}
		uc = (unsigned char)( (msg_size << (8 * (sizeof(msg_size) - 1 - i))) >> (8 * (sizeof(msg_size) - 1)));
		memcpy(((char**)buffers)[uHWrite % pool_cnt] + uLWrite, &uc, 1);
		++uLWrite;
		uHWrite = (uHWrite + uLWrite / buffer_size) % (2 * pool_cnt);
		uLWrite %= buffer_size;
	}
	uCurRestSize = buffer_size - uLWrite;

	uNextH = uHWrite % pool_cnt;
	if(!buffers[uNextH])
	{
		bf = buff_pool_new_buff(pool, buffer_size);
		if(!bf)
		{
			return enErr_NoMemory;
		}		
		buffers[uNextH] = bf;
	}
	if(uCurRestSize >= usize)
	{
		//copy data
		memcpy(((char**)buffers)[uNextH] + uLWrite, pdata, usize);
		uLWrite += usize;
		uHWrite = (uHWrite + uLWrite / buffer_size) % (2 * pool_cnt);
		uLWrite %= buffer_size;
	}
	else
	{
		// copy one rest buffer
		memcpy(((char**)buffers)[uNextH] + uLWrite, pdata, uCurRestSize);
		// copy other full buffer
		uH = (usize - uCurRestSize) / buffer_size;
		uL = (usize - uCurRestSize) % buffer_size;
		for(i = 0; i < uH; ++i)
		{
			uNextH = (uHWrite + 1 + i) % pool_cnt;
			if(!buffers[uNextH])
			{
				bf = buff_pool_new_buff(pool, buffer_size);
				if(!bf)
				{
					return enErr_NoMemory;
				}
				buffers[uNextH] = bf;
			}
			memcpy(buffers[uNextH], (const char*)pdata + uCurRestSize, buffer_size);
			uCurRestSize += buffer_size;
		}
		// copy last rest buffer
		uNextH = (uHWrite + 1 + uH) % pool_cnt;
		if(!buffers[uNextH])
		{
			bf = buff_pool_new_buff(pool, buffer_size);
			if(!bf)
			{
				return enErr_NoMemory;
			}
			buffers[uNextH] = bf;
		}
		memcpy(buffers[uNextH], (const char*)pdata + uCurRestSize, uL);
		uHWrite = (uHWrite + 1 + uH) % (2 * pool_cnt);
		uLWrite = uL;
	}
	release_memory_fence();
	sbuff->write = uHWrite << 16 | uLWrite;
//	buff_unlock(&sbuff->flag);
	return usize;
}



struct msg_buff
{
	void**					buffers;
	volatile unsigned int	write;
	volatile unsigned int	read;
	size_t					msg_type_size;
	unsigned short			buffer_size;
	unsigned short			pool_cnt;
	unsigned short			freeH;
	enum EnByteSize			en_byte;
	net_atomic_flag			rflag;
	net_atomic_flag			wflag;
	struct buff_pool*		pool;
};

struct msg_buff*
msg_buff_create(size_t msg_type_size, unsigned short buffer_size, unsigned short pool_cnt, struct buff_pool* pool)
{
	struct msg_buff * buff;
	assert(pool_cnt <= 0xefffu);
	//assert(buffer_size * msg_type_size == buff_pool_buffer_size(pool));
	buff = (struct msg_buff*)malloc(sizeof(struct msg_buff));
	if(!buff) return 0;
	buff->buffers = (void**)malloc(sizeof(void*) * pool_cnt);
	if(!buff->buffers)
	{
		free(buff);
		return 0;
	}
	memset(buff->buffers, 0, sizeof(void*) * pool_cnt);
	
	buff->msg_type_size = msg_type_size;
	buff->buffer_size = buffer_size;
	buff->pool_cnt = pool_cnt;
	buff->freeH = pool_cnt;
	buff->write = 0;
	buff->read = ((unsigned int)pool_cnt) << 16;
	buff->pool = pool;
	net_atomic_flag_clear(&buff->rflag);
	net_atomic_flag_clear(&buff->wflag);
	memeory_fence();
	return buff;
}

void
msg_buff_release(struct msg_buff* mbuff)
{
	unsigned short i;
	size_t pool_buffer_size;
	pool_buffer_size = mbuff->msg_type_size * mbuff->buffer_size;

	acquire_memory_fence();
	for(i = 0; i < mbuff->pool_cnt; ++i)
	{
		if(!mbuff->buffers[i])
		{
			continue;
		}
		buff_pool_del_buff(mbuff->pool, mbuff->buffers[i], pool_buffer_size);
		mbuff->buffers[i] = 0;
	}
	free(mbuff->buffers);
	free(mbuff);
	release_memory_fence();
}


int
msg_buff_write(struct msg_buff* mbuff, const void* msg)
{
	unsigned int uRead;
	unsigned int uWrite;
	unsigned int uHWrite;
	unsigned int uLWrite;
	unsigned int pool_cnt;
	unsigned int buffer_size;
	unsigned int pool_buffer_size;
	void* bf;

	bf = 0;

	net_lock(&mbuff->wflag);
	acquire_memory_fence();

	uRead = mbuff->read;
	uWrite = mbuff->write;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	pool_cnt = mbuff->pool_cnt;
	buffer_size = mbuff->buffer_size;
	pool_buffer_size = (unsigned int)(mbuff->msg_type_size * mbuff->buffer_size);

	if(uWrite == uRead)
	{
		net_unlock(&mbuff->wflag);
		return 0;
	}
	if(!mbuff->buffers[uHWrite % pool_cnt])
	{
		bf = buff_pool_new_buff(mbuff->pool, pool_buffer_size);
		if(!bf)
		{
			net_unlock(&mbuff->wflag);
			return enErr_NoMemory;
		}
		mbuff->buffers[uHWrite % pool_cnt] = bf;
	}
	memcpy(((char**)mbuff->buffers)[uHWrite % pool_cnt] + uLWrite * mbuff->msg_type_size, msg, mbuff->msg_type_size);
	++uLWrite;
	uHWrite = (uHWrite + uLWrite/buffer_size) % (2 * pool_cnt);
	uLWrite %= buffer_size;

	release_memory_fence();
	mbuff->write = uHWrite << 16 | uLWrite;
	net_unlock(&mbuff->wflag);
	return 1;
}

int
msg_buff_read(struct msg_buff* mbuff, void* msgs, size_t n)
{
	unsigned int uWrite;
	unsigned int uRead;
	unsigned int uHWrite;
	unsigned int uHRead;
	unsigned int uLWrite;
	unsigned int uLRead;
	unsigned int pool_cnt;
	unsigned int buffer_size;
	unsigned int write_size;
	size_t command_cnt;
	unsigned int i;

	net_lock(&mbuff->rflag);
	acquire_memory_fence();

	uWrite = mbuff->write;
	uRead = mbuff->read;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;
	pool_cnt = mbuff->pool_cnt;
	buffer_size = mbuff->buffer_size;

	write_size = pool_cnt * buffer_size - buff_get_space(pool_cnt, buffer_size, uHRead, uLRead, uHWrite, uLWrite);
	command_cnt = write_size < n? write_size : n;
	for(i = 0; i < command_cnt; ++i)
	{
		memcpy((char*)msgs + i * mbuff->msg_type_size, ((char**)mbuff->buffers)[uHRead % pool_cnt] + uLRead * mbuff->msg_type_size, mbuff->msg_type_size);
		++uLRead;
		uHRead = (uHRead + uLRead / buffer_size) % (2 * pool_cnt);
		uLRead %= buffer_size;
	}

	buff_gc_help(mbuff->buffers, mbuff->pool_cnt, (unsigned int)(mbuff->msg_type_size * mbuff->buffer_size),
		&mbuff->freeH, uHRead, uHWrite, mbuff->pool);

	release_memory_fence();
	mbuff->read = uHRead << 16 | uLRead;
	
	net_unlock(&mbuff->rflag);
	return (int)command_cnt;
}

unsigned int
msg_buff_size(struct msg_buff* mbuff)
{
	unsigned int uWrite;
	unsigned int uRead;
	unsigned int uHWrite;
	unsigned int uHRead;
	unsigned int uLWrite;
	unsigned int uLRead;
	unsigned int pool_cnt;
	unsigned int buffer_size;
	unsigned int write_size;

	acquire_memory_fence();

	uWrite = mbuff->write;
	uRead = mbuff->read;
	uHWrite = uWrite >> 16;
	uLWrite = (uWrite << 16) >> 16;
	uHRead = uRead >> 16;
	uLRead = (uRead << 16) >> 16;
	pool_cnt = mbuff->pool_cnt;
	buffer_size = mbuff->buffer_size;

	write_size = pool_cnt * buffer_size - buff_get_space(pool_cnt, buffer_size, uHRead, uLRead, uHWrite, uLWrite);

	return write_size;

}


#ifdef __cplusplus
}
#endif




