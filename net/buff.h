/*
 * buff.h
 *
 *  Created on: 2014-12-17
 *      Author: Random
 */

#ifndef BUFF_H_
#define BUFF_H_

// buff pool for sinwgle thread use
#include <stdint.h>
#include "buff_pool.h"


enum EnByteSize
{
	enByte8 = 1,
	enByte16 = 2,
	enByte24 = 3,
	enByte31 = 4
};

#define enErr_NoMemory -1
#define enErr_Recv_MsgSmall -2
#define enErr_Recv_MsgBig -3
#define enErr_Buff_NoEnough -4


struct recv_buff;
struct recv_buff*	
recv_buff_create(enum EnByteSize en_byte, uint16_t pool_cnt, struct buff_pool* pool);
void				
recv_buff_release(struct recv_buff* rbuff);
size_t				
recv_buff_prepare(struct recv_buff* rbuff, void** pdata);
int					
recv_buff_consume(struct recv_buff* rbuff, size_t usize);
int					
recv_buff_read(struct recv_buff* rbuff, void* buff, int usize);

struct send_buff;
struct send_buff*	
send_buff_create(enum EnByteSize en_byte, uint16_t pool_cnt,  struct buff_pool* pool);
void				
send_buff_release(struct send_buff* sbuff);
size_t				
send_buff_prepare(struct send_buff* sbuff, void** pdata);
void				
send_buff_consume(struct send_buff* sbuff, size_t usize);
int					
send_buff_write(struct send_buff* sbuff, const void* pdata, int size);

struct msg_buff;
struct msg_buff*	
msg_buff_create(size_t msg_type_size, uint16_t buffer_size, uint16_t pool_cnt, struct buff_pool* pool);
void				
msg_buff_release(struct msg_buff* mbuff);
int					
msg_buff_write(struct msg_buff* mbuff, const void* msg);
int					
msg_buff_read(struct msg_buff* mbuff, void* msgs, size_t n);
unsigned int		
msg_buff_size(struct msg_buff* mbuff);



#endif /* BUFF_H_ */

