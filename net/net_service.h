/*
 * net_service.h
 *
 *  Created on: 2015-06-08
 *      Author: Random
 */

#ifndef NET_SERVICE_H
#define NET_SERVICE_H

#include "buff.h"

#ifdef __cplusplus
extern "C" {
#endif

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
	int						read_buff_version;				//read buff version, default RECV_BUFF_USE_BUFF
};

struct net_event
{
	unsigned int			events;
	net_socket				nd;
	param_type				data;
};


#if defined(NET_BUILD_AS_DLL)

#if defined(NET_CORE) || defined(NET_LIB)
#define NET_API __declspec(dllexport)
#else
#define NET_API __declspec(dllimport)
#endif						

#else

#define NET_API		extern

#endif

/**
* creat a net_service
**/
NET_API struct net_service*			
net_create(int size);
/**
* close the service, only this function is not thread safe
**/
NET_API void						
net_close(struct net_service* service);
/**
* do something like epoll_wait。you can call it on async thread
**/
NET_API int							
net_wait(struct net_service* service, int timeout);

/**
 * delay send socket data
 * max_cnt : max number of send sockets
 */
NET_API int                         
net_delay(struct net_service* service, int max_cnt);
/**
* get events
**/
NET_API int							
net_queue(struct net_service* service, struct net_event * events, int maxevents);
/**
* listen port，you can listen some port use the same net_service
**/
NET_API net_socket					
net_listen(struct net_service* service, const char* host,  unsigned short port, unsigned short backlog);
/**
* if listening socket have Eve_Accept event , call this function you can get a client net_socket
**/
NET_API net_socket					
net_accept(struct net_service* service, net_socket nd);
/**
* connect remote service
**/
NET_API net_socket					
net_connect(struct net_service* service, const char* ip, unsigned short port);
/**
*	cfg the net_socket
*	you can write/read net_socket after call @net_socket_cfg
*	you can set the net buff by config
**/
NET_API int							
net_socket_cfg(struct net_service* service, net_socket nd, struct net_config* config);
/**
* close net_socket
* send_rest: if you want send all rest data in buff, set to 1
* 
**/
NET_API void						
net_socket_close(struct net_service* service, net_socket nd, char send_rest);
/**
* read a msg with max size defined by enByte  on @net_socket_cfg.
* if buff not enough, it will return the current msg size.
* so only the return 0 < value <= usize, the msg read ok 
**/
NET_API int							
net_socket_read(struct net_service* service, net_socket nd, void* buff, int usize);
/**
* write a msg to net_socket
* if the net_socket's write_buff not enough, it will send faild
**/
NET_API int							
net_socket_write(struct net_service* service, net_socket nd, const void* buff, int usize, char delay);
/**
* ctl you param data, if data is null, will return the data current ctl
*/
NET_API param_type					
net_socket_ctl(struct net_service* service, net_socket nd, param_type* data);
/**
*  current net_socket size, also include listening sockets, connecting sockets
*/
NET_API int							
net_socket_size(struct net_service* service);

/**
 * get socket ip and port
 */
NET_API int
net_socket_ip_port(struct net_service* service, net_socket nd, char* ip, unsigned short* port);

NET_API int 
net_socket_error(struct net_service* service, net_socket nd);

NET_API int 
net_error(struct net_service* service);

#ifdef __cplusplus
}
#endif

#endif /* NET_SERVICE_H_ */

