/*
 * net_service.c
 *
 *  Created on: 2015年12月14日
 *      Author: Random
 */




#include <stdlib.h>
#include "net_atomic.h"
#include "../tool/ffid.h"
#include "../tool/sbtree.h"
#include "buff.h"
#include "net_service.h"


#ifdef NET_WIN
#include <winsock2.h>
#include <mswsock.h>
#include <Windows.h>

#define net_get_error WSAGetLastError
#define NET_INVALID_SOCKET INVALID_SOCKET
#define NET_SOCKET	SOCKET
#define NET_SERVICE_TYPE	HANDLE
#define net_close_service_fd	CloseHandle
#define net_close_fd			closesocket

struct system_data
{
	OVERLAPPED					overlapped;
	int							op_type;
	WSABUF						data_buf;
	DWORD						rc_bytes;
	DWORD						flag;
};

#define system_session_define(m)	struct system_data m;

#else

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
 #include <fcntl.h>
 #include <unistd.h> 

#define net_get_error()	errno
#define NET_INVALID_SOCKET -1
#define NET_SOCKET	int
#define NET_SERVICE_TYPE	int
#define net_close_service_fd	close
#define net_close_fd			close

#define system_session_define(m)

#endif //NET_WIN

#define OP_NET_NONE  0



struct listen_session;

struct read_session
{
	system_session_define(sm)
	ffid_vtype					id;
	struct recv_buff*			rbuff;
	int							op;
	char						etflag;
};

struct write_session
{
	system_session_define(sm)
	ffid_vtype					id;
	struct send_buff*			sbuff;
	NET_SOCKET					fd;
	int							op;
	char						send_rest;
	char						etflag;
};

struct net_session
{
	ffid_vtype					id;
	NET_SOCKET					fd;
	struct read_session*		rsession;
	struct write_session*		wsession;
	struct listen_session*		lsession;
	unsigned int				events;	
	param_type					data;
	char						in_queue;	
	char						connect_flag;
};

struct net_service
{
	NET_SERVICE_TYPE			net_service_fd;
	net_atomic_flag				id_lock;
	struct ffid					*socket_ids;
	net_atomic_flag				*session_lock;
	struct net_session			**sessions;
	struct buff_pool			*pool;
	size_t						size;
	struct msg_buff				*queue;
	net_atomic_flag				close_lock;
	struct sbtree_node*			close_root;
};


int net_init();
void net_cleanup();
void release_listen_session(struct listen_session* lsession);
NET_SERVICE_TYPE net_create_service_fd(int size);
int ctl_socket_async(NET_SOCKET fd);
int post_read(struct net_service* service, struct net_session* session);
int post_write(struct net_service* service, struct net_session* session);

NET_SOCKET
create_socket()
{
	return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void
release_net_service(struct net_service* service)
{
	if(!service)
	{
		return;
	}
	if(service->socket_ids)
	{
		ffid_release(service->socket_ids);
	}
	if(service->session_lock)
	{
		free(service->session_lock);
	}
	if(service->sessions)
	{
		free(service->sessions);
	}
	if(service->net_service_fd)
	{
		net_close_service_fd(service->net_service_fd);
	}
	if(service->pool)
	{
		buff_pool_release(service->pool);
	}
	if(service->queue)
	{
		msg_buff_release(service->queue);
	}
	sb_tree_clean(&service->close_root);
	free(service);

	net_cleanup();

}

NET_API struct net_service*
net_create(int size)
{
	struct net_service* service;

	if(!net_init())
	{
		return 0;
	}

	service = (struct net_service*)malloc(sizeof(struct net_service));
	if(!service)
	{
		return 0;
	}
	memset(service, 0, sizeof(struct net_service));
	service->size = size;
	service->socket_ids = ffid_create((unsigned short)size, 1);
	if(!service->socket_ids )
	{
		release_net_service(service);
		return 0;
	}
	service->session_lock = (net_atomic_flag*)malloc(sizeof(net_atomic_flag) * size);
	if(!service->session_lock)
	{
		release_net_service(service);
		return 0;
	}
	memset(service->session_lock , 0, sizeof(net_atomic_flag) * size);
	service->sessions = (struct net_session**)malloc(sizeof(struct net_session*) * size);
	if(!service->sessions )
	{
		release_net_service(service);
		return 0;
	}
	memset(service->sessions, 0, sizeof(struct net_session*) * size);
	service->net_service_fd = net_create_service_fd(size);
	if(!service->net_service_fd)
	{
		release_net_service(service);
		return 0;
	}
	service->pool = buff_pool_create(size * sizeof(ffid_vtype), 1);
	if(!service->pool)
	{
		release_net_service(service);
		return 0;
	}
	// create 4 * size queue ， if too many closed sessions's id in queue， it have space to cache the new session id
	service->queue = msg_buff_create(sizeof(ffid_vtype), size, 4, service->pool);
	if(!service->queue)
	{
		release_net_service(service);
		return 0;
	}
	return service;
}


void
release_read_session(struct read_session* rsession)
{
	if(!rsession)
	{
		return;
	}
	if(rsession->rbuff)
	{
		recv_buff_release(rsession->rbuff);
	}
	free(rsession);
}

struct read_session*
create_read_session(enum EnByteSize en_byte, uint16_t pool_cnt, struct buff_pool* pool, int version)
{
	struct read_session* rsession;
	rsession = (struct read_session*)malloc(sizeof(struct read_session));
	if(!rsession)
	{
		return 0;
	}
	memset(rsession, 0, sizeof(struct read_session));
	rsession->rbuff = recv_buff_create(en_byte, pool_cnt, pool, version);
	if(!rsession->rbuff )
	{
		release_read_session(rsession);
		return 0;
	}
	return rsession;
}

void
release_write_session(struct write_session* wsession)
{
	if(!wsession)
	{
		return;
	}
	if(wsession->sbuff)
	{
		send_buff_release(wsession->sbuff);
	}
	if(wsession->fd != NET_INVALID_SOCKET)
	{
		net_close_fd(wsession->fd);
	}
	free(wsession);
}

struct write_session*
create_write_session(enum EnByteSize en_byte, uint16_t pool_cnt,  struct buff_pool* pool)
{
	struct write_session* wsession;
	wsession = (struct write_session*)malloc(sizeof(struct write_session));
	if(!wsession)
	{
		return 0;
	}
	memset(wsession, 0, sizeof(struct write_session));
	wsession->sbuff = send_buff_create(en_byte, pool_cnt, pool);
	if(!wsession->sbuff)
	{
		release_write_session(wsession);
		return 0;
	}
	wsession->fd = NET_INVALID_SOCKET;
	return wsession;
}


ffid_vtype
add_net_session(struct net_service* service, struct net_session *session)
{
	ffid_vtype id;
	unsigned short index;

	if(!session)
	{
		return 0;
	}
	net_lock(&service->id_lock);
	id = ffid_new_id(service->socket_ids, &index);
	if(id == 0)
	{
		net_unlock(&service->id_lock);
		return 0;
	}
	net_unlock(&service->id_lock);
	net_lock(&service->session_lock[index]);
	service->sessions[index] = session;
	session->id = id;
	net_unlock(&service->session_lock[index]);
	return id;
}

void
release_net_session(struct net_session* session)
{
	if(!session)
	{
		return;
	}
	if(session->rsession && session->rsession->op == OP_NET_NONE)
	{
		release_read_session(session->rsession);
	}
	if(session->wsession && session->wsession->op == OP_NET_NONE)
	{
		release_write_session(session->wsession);
	}
	release_listen_session(session->lsession);
	free(session);
}

struct net_session*
create_net_session()
{
	struct net_session* session;
	session = (struct net_session*)malloc(sizeof(struct net_session));
	if(!session)
	{
		return 0;
	}
	memset(session, 0, sizeof(struct net_session));
	return session;
}


NET_API int
net_socket_size(struct net_service* service)
{
	int s = 0;
	net_lock(&service->id_lock);
	s = ffid_size(service->socket_ids);
	net_unlock(&service->id_lock);
	return s;
}

NET_API void
net_close(struct net_service* service)
{
	// clean all
	unsigned short index;
	ffid_vtype id;

	index = 0;
	for(index = 0; index < service->size; ++index)
	{
		id = ffid_id(service->socket_ids, index);
		if(!id) continue;
		net_socket_close(service, id, 0);
	}
	// notation there can't ensure all socket write over
	while(service->close_root || net_wait(service, 2000) > 0);
	release_net_service(service);
}

static int
push_queue(struct net_service* service, struct net_session* session, unsigned int event)
{
	long long s;
	int ret;

	session->events |= event;
	if(session->in_queue)
	{
		return 1;
	}
	s = session->id;
	session->in_queue = 1;
	session->connect_flag = 0;
	// maybe queue is full, for some closed session id in queue
	// you'd better check if the message in queue
	ret = msg_buff_write(service->queue, &s);
	return ret;
}

int
push_queue_with_lock(struct net_service* service, net_socket nd, unsigned int event)
{
	struct net_session* session;
	unsigned short index;
	int ret;

	if(!service || nd == 0)
	{
		return 0;
	}
	index = ffid_index(service->socket_ids, nd);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->id != nd)
	{
		net_unlock(&service->session_lock[index]);
		return 0;
	}
	ret = push_queue(service, session, event);
	net_unlock(&service->session_lock[index]);
	return ret;
}

#define r_min(a, b) (a) < (b) ? (a):(b)

NET_API int
net_queue(struct net_service* service, struct net_event * events, int maxevents)
{
	unsigned int msg[128];
	int cnt;
	int ret;
	int event_index;
	int i;
	struct net_session* session;

	event_index = 0;
	while(event_index < maxevents)
	{
		cnt = r_min(sizeof(msg)/sizeof(msg[0]), (unsigned int)(maxevents - event_index));
		ret = msg_buff_read(service->queue, msg, cnt);
		for(i = 0; i < ret; ++i)
		{
			cnt = ffid_index(service->socket_ids, msg[i]);
			net_lock(&service->session_lock[cnt]);
			session = service->sessions[cnt];
			if(session && session->id == msg[i])
			{
				session = service->sessions[cnt];
				events[event_index].events = session->events;
				events[event_index].nd = session->id;
				events[event_index].data = session->data;
				session->events = 0;
				session->in_queue = 0;
				++event_index;
			}
			net_unlock(&service->session_lock[cnt]);
		}
		if(ret < cnt)
		{
			break;
		}
	}
	return event_index;
}


NET_API int
net_socket_cfg(struct net_service* service, net_socket nd, struct net_config* config)
{
	unsigned short index;
	struct net_session* session;
	int ret;

	if(!service || !config || nd == 0)
	{
		return -6;
	}
	index = ffid_index(service->socket_ids, nd);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->rsession || session->wsession || session->connect_flag || session->lsession)
	{
		net_unlock(&service->session_lock[index]);
		return -2;
	}

	if( ctl_socket_async(session->fd) )
	{
		net_unlock(&service->session_lock[index]);
		return -3;
	}
	
	session->rsession = create_read_session(config->enByte, config->read_buff_cnt, config->pool, config->read_buff_version);
	if(!session->rsession)
	{
		net_unlock(&service->session_lock[index]);
		return -4;
	}
	session->rsession->id = nd;
	session->wsession = create_write_session(config->enByte, config->write_buff_cnt, config->pool);
	if(!session->wsession)
	{
		net_unlock(&service->session_lock[index]);
		release_read_session(session->rsession);
		session->rsession = 0;
		return -5;
	}

	session->wsession->id = nd;
	ret = post_read(service, session);
	net_unlock(&service->session_lock[index]);
	return ret;
}

NET_API param_type
net_socket_ctl(struct net_service* service, net_socket nd, param_type* data)
{
	unsigned short index;
	struct net_session* session;
	param_type oldData;

	if(!service)
	{
		return 0;
	}
	if(!nd)
	{
		return 0;
	}
	index = ffid_index(service->socket_ids, nd);

	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->id != nd)
	{
		net_unlock(&service->session_lock[index]);
		return 0;
	}
	oldData = session->data;
	if(data)
	{
		session->data = *data;
	}
	net_unlock(&service->session_lock[index]);
	return oldData;
}

NET_API int
net_socket_read(struct net_service* service, net_socket nd, void* buff, int usize)
{
	unsigned short index;
	struct net_session* session;
	int ret;

	if(!service)
	{
		return -1;
	}
	if(!nd)
	{
		return -1;
	}
	index = ffid_index(service->socket_ids, nd);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->id != nd || !session->rsession)
	{
		net_unlock(&service->session_lock[index]);
		return -1;
	}
	post_read(service, session);
	ret = recv_buff_read(session->rsession->rbuff, buff, usize);
	net_unlock(&service->session_lock[index]);
	return ret;
}


NET_API int
net_socket_write(struct net_service* service, net_socket nd, const void* buff, int usize)
{
	unsigned short index;
	struct net_session* session;
	int ret;

	if(!service)
	{
		return -1;
	}
	if(!nd)
	{
		return -1;
	}
	index = ffid_index(service->socket_ids, nd);

	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->id != nd || !session->wsession)
	{
		net_unlock(&service->session_lock[index]);
		return -1;
	}
	ret = send_buff_write(session->wsession->sbuff, buff, usize);
	post_write(service, session);
	net_unlock(&service->session_lock[index]);
	return ret;
}

#include "iocp_service.c"
#include "epoll_service.c"


