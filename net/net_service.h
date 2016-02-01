/*
 * net_service.h
 *
 *  Created on: 2015-06-08
 *      Author: Random
 */

#ifndef NET_SERVICE_H
#define NET_SERVICE_H

#include "buff.h"


#define ERROR_NET_SOCKET 0

typedef unsigned int net_socket;
typedef unsigned long long param_type;
struct net_service;


#define Eve_Accept 1
#define Eve_Read 2
#define Eve_Connect 4
#define Eve_Post_Listen_Error	(1 << 29)
#define Eve_Error	(1 << 30)


struct net_config
{
	enum EnByteSize			enByte;							//defined in buff.h, which size do you want to select
	unsigned short			read_buff_cnt;					//your read buff of read_buff_cnt
	unsigned short			write_buff_cnt;					//your write buff of write_buff_cnt
	struct buff_pool*		pool;							//a buff pool
};

struct net_event
{
	unsigned int			events;
	net_socket				nd;
	param_type				data;
};

/**
* creat a net_service
**/
struct net_service*			net_create(int size);
/**
* close the service, only this function is not thread safe
**/
void						net_close(struct net_service* service);
/**
* do something like epoll_wait。you can call it on async thread
**/
int							net_wait(struct net_service* service, int timeout);
/**
* get events
**/
int							net_queue(struct net_service* service, struct net_event * events, int maxevents);
/**
* listen port，you can listen some port use the same net_service
**/
net_socket					net_listen(struct net_service* service, unsigned short port, unsigned short listen_cnt);
/**
* if listening socket have Eve_Accept event , call this function you can get a client net_socket
**/
net_socket					net_accept(struct net_service* service, net_socket nd);
/**
* connect remote service
**/
net_socket					net_connect(struct net_service* service, const char* ip, unsigned short port);
/**
*	cfg the net_socket
*	you can write/read net_socket after call @net_socket_cfg
*	you can set the net buff by config
**/
int							net_socket_cfg(struct net_service* service, net_socket nd, struct net_config* config);
/**
* close net_socket
* send_rest: if you want send all rest data in buff, set to 1
* 
**/
void						net_socket_close(struct net_service* service, net_socket nd, char send_rest);
/**
* read a msg with max size defined by enByte  on @net_socket_cfg.
* if buff not enough, it will return the current msg size.
* so only the return 0 < value <= usize, the msg read ok 
**/
int							net_socket_read(struct net_service* service, net_socket nd, void* buff, int usize);
/**
* write a msg to net_socket
* if the net_socket's write_buff not enough, it will send faild
**/
int							net_socket_write(struct net_service* service, net_socket nd, const void* buff, int usize);
/**
* ctl you param data, if data is null, will return the data current ctl
*/
param_type					net_socket_ctl(struct net_service* service, net_socket nd, param_type* data);
/**
*  current net_socket size, also include listening sockets, connecting sockets
*/
int							net_socket_size(struct net_service* service);
/**
* sleep
**/
void						net_service_sleep(long ms);

#endif /* NET_SERVICE_H_ */

