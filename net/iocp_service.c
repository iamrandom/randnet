/*
 * iocp_service.c
 *
 *  Created on: 2015-6-8
 *	  Author: Random
 */
//#define NET_WIN
#ifdef NET_WIN



#include <Windows.h>


#define	OP_NET_ACCEPT  1
#define	OP_NET_READ	2
#define	OP_NET_WRITE	4
#define	OP_NET_CONNECT	8


struct iocp_data
{
	OVERLAPPED					overlapped;
	int							op_type;
};

struct accept_session
{
	OVERLAPPED					overlapped;
	int							op;
	NET_SOCKET					accept_socket;
	ffid_vtype					id;
	DWORD 						recv_bytes;
	char						data_buf[(sizeof(struct sockaddr_in6) + 32) * 2];
	int							index;
};

struct iocp_listen_session
{
	char						ip[64];
	unsigned short 				port;
	unsigned short				listen_cnt;
	struct msg_buff*			socket_queue;
	struct buff_pool*			pool;
};

struct connect_session
{
	OVERLAPPED					overlapped;
	int							op;
	DWORD						send_bytes;
	ffid_vtype					id;
	NET_SOCKET					s;
};

NET_SERVICE_TYPE net_create_service_fd(int size)
{
	return CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
}

volatile net_atomic_flag init_lock = NET_ATOMIC_FLAG_INIT;
volatile int init_cnt = 0;




int
net_init()
{
	WSADATA wsa_data;
	WORD version;

	version = MAKEWORD(2, 2);
	net_lock(&init_lock);
	if(0 == init_cnt)
	{
		if(0 != WSAStartup(version, &wsa_data))
		{
			net_unlock(&init_lock);
			return 0;
		}
		if(version != wsa_data.wVersion)
		{
			WSACleanup();
			net_unlock(&init_lock);
			return 0;
		}
	}
	++init_cnt;
	net_unlock(&init_lock);
	return 1;
}

void
net_cleanup()
{
	net_lock(&init_lock);
	if(1 == init_cnt)
	{
		WSACleanup();
	}
	--init_cnt;
	net_unlock(&init_lock);
}

void
release_listen_session(struct listen_session* lsn)
{
	NET_SOCKET s[32];
	int cnt, i;

	struct iocp_listen_session *lsession;

	if(!lsn)
	{
		return;
	}
	lsession = (struct iocp_listen_session *) lsn;
	if(lsession->socket_queue)
	{
		while((cnt = msg_buff_read(lsession->socket_queue, s, sizeof(s)/sizeof(s[0]))))
		{
			for(i = 0; i < cnt; ++i)
			{
				net_close_fd(s[i]);
			}
		}
		msg_buff_release(lsession->socket_queue);
	}
	free(lsession);
}

struct listen_session*
create_listen_session(struct net_service* service, unsigned short port, unsigned short listen_cnt)
{
	struct iocp_listen_session* lsession;
	size_t buff_size;
	lsession = (struct iocp_listen_session*)(malloc(sizeof(struct iocp_listen_session)));
	if(!lsession)
	{
		return 0;
	}
	memset(lsession, 0, sizeof(struct iocp_listen_session));
	buff_size = buff_pool_buffer_size(service->pool);
	lsession->socket_queue = msg_buff_create((uint16_t)sizeof(NET_SOCKET), (uint16_t)(buff_size / sizeof(NET_SOCKET)), 1, service->pool);
	if(!lsession->socket_queue)
	{
		release_listen_session((struct listen_session*)lsession);
		return 0;
	}
	lsession->listen_cnt = listen_cnt;
	lsession->port = port;
	return (struct listen_session*)lsession;
}


void
release_accept_session(struct accept_session* asession)
{
	if(!asession)
	{
		return;
	}
	if(asession->accept_socket)
	{
		net_close_fd(asession->accept_socket);
	}
	free(asession);
}

struct accept_session*
create_accept_session()
{
	struct accept_session* asession;
	asession = (struct accept_session*)malloc(sizeof(struct accept_session));
	if(!asession)
	{
		return 0;
	}
	memset(asession, 0, sizeof(struct accept_session));
	return asession;
}

#include <time.h>

#define print_error()
	// printf("error: %s:%d	%s %d %d\n", __FILE__, __LINE__, __FUNCTION__, net_get_error(), (int)clock());
	// fflush(stdout);



//#ifndef ERROR_ABANDONED_WAIT_0
//#define ERROR_ABANDONED_WAIT_0 0x2df|735
//#endif
struct net_session*
create_and_add_net_session(struct net_service* service, NET_SOCKET s)
{
	struct net_session* session;
	ffid_vtype id;

	session = create_net_session();
	if(!session)
	{
		return 0;
	}
	id = add_net_session(service, session);
	if(id == 0)
	{
		release_net_session(session);
		return 0;
	}
	session->fd = s;
	return session;
}

int
post_listen(struct net_service* service, struct net_session* session, struct accept_session* asession)
{
	NET_SOCKET accept_socket;
	int err;

	accept_socket = socket(session->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if(NET_INVALID_SOCKET == accept_socket)
	{
		return -1;
	}

	CreateIoCompletionPort((HANDLE)accept_socket, service->net_service_fd, (ULONG_PTR)accept_socket, sizeof(NET_SOCKET));
	memset(asession, 0, sizeof(struct accept_session));
	asession->id = session->id;
	asession->accept_socket = accept_socket;
	asession->op = OP_NET_ACCEPT;

	if(!AcceptEx(
		session->fd,
		accept_socket,
		asession->data_buf,
		0,
		sizeof(asession->data_buf)/2,
		sizeof(asession->data_buf)/2,
		&asession->recv_bytes,
		&asession->overlapped
	))
	{
		err = net_get_error();
		if(ERROR_IO_PENDING != err)
		{
			net_close_fd(accept_socket);
			return err;
		}
	}
	return NO_ERROR;
}



NET_SOCKET bind_help(struct net_service* service, struct addrinfo * info)
{
	NET_SOCKET s;

	s = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(NET_INVALID_SOCKET == s)
	{
		return NET_INVALID_SOCKET;
	}
	CreateIoCompletionPort((HANDLE)s, service->net_service_fd, (ULONG_PTR)s, sizeof(NET_SOCKET));
	if(bind(s, info->ai_addr, info->ai_addrlen))
	{
		net_close_fd(s);
		return NET_INVALID_SOCKET;
	}
	return s;
}


NET_API net_socket
net_listen(struct net_service* service, const char* host, unsigned short port, unsigned short listen_cnt)
{
	ffid_vtype id;
	NET_SOCKET listen_socket;
	struct net_session* session;
	
	struct accept_session* asession;
	int i;
	struct net_addr addr;

	if(net_addr_help(&addr, host, port, AF_UNSPEC, AI_PASSIVE))
	{
		return 0;
	}
	listen_socket = bind_help(service, addr.ai_list);	

	if(NET_INVALID_SOCKET == listen_socket)
	{
		free_net_addr(&addr);
		return 0;
	}
	
	if(listen(listen_socket, listen_cnt))
	{
		free_net_addr(&addr);
		net_close_fd(listen_socket);
		return 0;
	}
	session = create_net_session();
	if(!session)
	{
		free_net_addr(&addr);
		net_close_fd(listen_socket);
		return 0;
	}
	session->ai_family = addr.ai_list->ai_family;
	session->fd = listen_socket;
	session->lsession = create_listen_session(service, port, listen_cnt);
	if(!session->lsession)
	{
		free_net_addr(&addr);
		release_net_session(session);
		net_close_fd(listen_socket);
		return 0;
	}
	sockaddr_ip_port(addr.ai_list->ai_addr, session->lsession->ip, &(session->lsession->port));

	free_net_addr(&addr);
	
	id = add_net_session(service, session);
	if(!id)
	{
		release_net_session(session);
		net_close_fd(listen_socket);
		return 0;
	}

	for(i = 0; i < listen_cnt; ++i)
	{
		asession = create_accept_session();
		if(asession)
		{
			if(!post_listen(service, session, asession))
			{
				asession->index = i;
				continue;
			}
			release_accept_session(asession);
		}
		net_socket_close(service, id, 0);
		return 0;
	}
	return id;
}

void
handle_accept(struct net_service* service, int ret, int err, struct accept_session*	asession)
{
	struct net_session*	session;

	unsigned int			session_index;

	if( !asession || asession->id == 0)
	{
		release_accept_session(asession);
		return;
	}
	session_index = ffid_index(service->socket_ids, asession->id);
	net_lock(&service->session_lock[session_index]);
	session = service->sessions[session_index];

	if (!ret && err)
	{
		net_close_fd(asession->accept_socket);
		if (!session || !session->lsession || session->id != asession->id)
		{
			net_unlock(&service->session_lock[session_index]);
			push_queue_with_lock(service, asession->id, Eve_Post_Listen_Error, err);
			release_accept_session(asession);
			return;
		}
	}
	else
	{
		if (!session || !session->lsession || session->id != asession->id)
		{
			net_unlock(&service->session_lock[session_index]);
			push_queue_with_lock(service, asession->id, Eve_Post_Listen_Error, err);
			release_accept_session(asession);
			return;
		}
		if (!push_queue(service, session, Eve_Accept, err))
		{
			net_close_fd(asession->accept_socket);
		}
		else if (msg_buff_write(((struct iocp_listen_session*)session->lsession)->socket_queue, (void*)&asession->accept_socket) != 1)
		{
			net_close_fd(asession->accept_socket);
		}
		else
		{
			setsockopt(asession->accept_socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&session->fd, sizeof(session->fd));

		}
	}

	net_unlock(&service->session_lock[session_index]);
	asession->accept_socket = 0;
	if(post_listen(service, session, asession))
	{
		release_accept_session(asession);
		push_queue_with_lock(service, session->id, Eve_Post_Listen_Error, err);
	}
}


int
post_read(struct net_service* service, struct net_session* session)
{
	struct read_session* rsession;
	void* data;
	size_t size;
	int err, msgcnt;

	size = 0;
	data = 0;
	msgcnt = 0;

	if(!service)
	{
		return -1;
	}

	if(!session || !session->rsession)
	{
		return -1;
	}
	rsession = session->rsession;

	if(rsession->op == OP_NET_READ)
	{
		return 0;
	}

	for (;;)
	{
		size = recv_buff_prepare(rsession->rbuff, &data);
		if (size == 0)
		{
			return 0;
		}
	
		err = recv(session->fd, (char*)data, (int)size, 0);
		msgcnt = recv_buff_consume(rsession->rbuff, err < 0? 0 : (size_t)err);
		if (err > 0)
		{
			if(msgcnt > 0)
			{
				// notify only have new msg
				push_queue(service, session, Eve_Read, 0);
			}
			else if(msgcnt < 0)
			{
				// error happend
				print_error();
				push_queue(service, session, Eve_Error, net_get_error());
				return 0;
			}
		}
		else if (err == 0)
		{
			// socket closed
			print_error();
			push_queue(service, session, Eve_Error, net_get_error());
			return 0;
		}
		else
		{
			if (net_get_error() == WSAEWOULDBLOCK)
			{
				break;
			}
			print_error();
			push_queue(service, session, Eve_Error, net_get_error());
			return 0;
		}
	}

	rsession->op = OP_NET_READ;
	rsession->sm.op_type = OP_NET_READ;
	rsession->sm.data_buf.buf = 0;
	rsession->sm.data_buf.len = 0;
	rsession->sm.rc_bytes = 0;
	rsession->sm.flag = 0;

	if(WSARecv(
		session->fd, &rsession->sm.data_buf, 1,
		&rsession->sm.rc_bytes, &rsession->sm.flag,
		&rsession->sm.overlapped, 0)
	)
	{
		err = net_get_error();
		if(WSA_IO_PENDING != err)
		{
			rsession->op = OP_NET_NONE;
			rsession->sm.op_type = OP_NET_NONE;
			rsession->sm.data_buf.buf = 0;
			rsession->sm.data_buf.len = 0;
			return -1;
		}
	}
	return 0;
}

int
post_write(struct net_service* service, struct net_session* session)
{
	struct write_session* wsession;
	void* data;
	size_t size;
	int err;

	size = 0;
	data = 0;
	if( !service)
	{
		return -1;
	}

	if(!session->wsession)
	{
		return -1;
	}

	wsession = session->wsession;
	if(wsession->op == OP_NET_WRITE)
	{
		return 0;
	}
	size = send_buff_prepare(wsession->sbuff, &data);
	if(size == 0)
	{
		return 0;
	}
	wsession->op = OP_NET_WRITE;
	wsession->sm.op_type = OP_NET_WRITE;
	wsession->sm.data_buf.buf = (char*)data;
	wsession->sm.data_buf.len = (unsigned long)size;
	wsession->sm.rc_bytes = 0;
	wsession->sm.flag = 0;

	if(WSASend(
		session->fd, &wsession->sm.data_buf, 1,
		&wsession->sm.rc_bytes, wsession->sm.flag, &wsession->sm.overlapped, 0)
	)
	{
		err = net_get_error();
		if(WSA_IO_PENDING != err)
		{
			wsession = session->wsession;
			wsession->op = OP_NET_NONE;
			wsession->sm.op_type = OP_NET_NONE;
			wsession->sm.data_buf.buf = 0;
			wsession->sm.data_buf.len = 0;
			return -1;
		}
	}
	return 1;
}


int
post_rest_write(struct net_service* service, struct write_session* wsession)
{
	void* data;
	size_t size;
	int err;

	size = 0;
	data = 0;

	if(!service || wsession)
	{
		return -1;
	}

	size = send_buff_prepare(wsession->sbuff, &data);
	if(size == 0)
	{
		return 0;
	}
	if(wsession->op == OP_NET_WRITE)
	{
		return 0;
	}
	wsession->op = OP_NET_WRITE;
	wsession->sm.op_type = OP_NET_WRITE;
	wsession->sm.data_buf.buf = (char*)data;
	wsession->sm.data_buf.len = (unsigned long)size;
	wsession->sm.rc_bytes = 0;
	wsession->sm.flag = 0;

	if(WSASend(
		wsession->fd, &wsession->sm.data_buf, 1,
		&wsession->sm.rc_bytes, wsession->sm.flag, &wsession->sm.overlapped, 0)
	)
	{
		err = net_get_error();
		if(WSA_IO_PENDING != err)
		{
			return -1;
		}
	}
	return 1;
}


NET_API net_socket
net_accept(struct net_service* service, net_socket fd)
{
	struct net_session* session;
	struct net_session* accept_session;
	unsigned short index;
	int ai_family;
	NET_SOCKET s;

	if(!service || fd == 0)
	{
		return 0;
	}
	index = ffid_index(service->socket_ids, fd);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || !session->lsession || session->id != fd)
	{
		net_unlock(&service->session_lock[index]);
		return 0;
	}
	if(msg_buff_read(((struct iocp_listen_session*)session->lsession)->socket_queue, &s, 1) != 1)
	{
		net_unlock(&service->session_lock[index]);
		return 0;
	}
	ai_family = session->ai_family;
	net_unlock(&service->session_lock[index]);

	accept_session = create_and_add_net_session(service, s);
	if(!accept_session)
	{
		net_close_fd(s);
		return 0;
	}
	accept_session->ai_family = ai_family;
	return accept_session->id;
}

int
ctl_socket_async(NET_SOCKET fd)
{
	unsigned long async_flag;
	async_flag = 1;
	return ioctlsocket(fd, FIONBIO, &async_flag);
}

void
release_connect_session(struct connect_session* csession)
{
	if(!csession)
	{
		return;
	}
	free(csession);
}

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010
#endif


void
handle_write(struct net_service* service, int ret, int err, struct write_session* wsession, size_t bytes)
{
	struct net_session* session;
	unsigned short index;
	unsigned int events;
	ffid_vtype fd;

	if(!wsession)
	{
		return;
	}
	fd = wsession->id;
	if(fd == 0)
	{
		release_write_session(wsession);
		return;
	}

	index = ffid_index(service->socket_ids, fd);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	wsession->op = OP_NET_NONE;
	if(ret && bytes >= 0)
	{
		send_buff_consume(wsession->sbuff, bytes);
	}

	if(!session || session->id != fd)
	{
		if(ret && wsession->send_rest && post_rest_write(service, wsession) > 0)
		{
			net_unlock(&service->session_lock[index]);
			return;
		}
		release_write_session(wsession);
		net_unlock(&service->session_lock[index]);
		return;
	}

	ret = post_write(service, session);
	events = 0;
	if(ret < 0)
	{
		events |= Eve_Error;
		print_error();
	}

	if (!events || push_queue(service, session, events, err) > 0)
	{
		net_unlock(&service->session_lock[index]);
		return;
	}
	net_unlock(&service->session_lock[index]);
	net_socket_close(service, fd, 0);
}


void
handle_read(struct net_service* service, int ret, int err, struct read_session* rsession, size_t bytes)
{
	struct net_session* session;
	unsigned short index;
	unsigned int events;

	if(!rsession)
	{
		return;
	}

	if(rsession->id == 0)
	{
		release_read_session(rsession);
		return;
	}

	index = ffid_index(service->socket_ids, rsession->id);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->id != rsession->id)
	{
		release_read_session(rsession);
		net_unlock(&service->session_lock[index]);
		return;
	}
	rsession->op = OP_NET_NONE;

	events = Eve_Read;
	if((!ret && err) || post_read(service, session) )
	{
		events |= Eve_Error;
		print_error();
	}
	push_queue(service, session, events, err);
	net_unlock(&service->session_lock[index]);
}


void
handle_connect(struct net_service* service, int ret, int err, struct connect_session *csession, size_t bytes)
{
	if(!csession)
	{
		return;
	}
	if(!csession->id)
	{
		release_connect_session(csession);
		return;
	}

	if(!ret && err)
	{
		print_error();
		push_queue_with_lock(service, csession->id, Eve_Connect | Eve_Error, err);
		release_connect_session(csession);
		return;
	}
	err = setsockopt(csession->s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, 0, 0);
	push_queue_with_lock(service, csession->id, Eve_Connect, err);
	release_connect_session(csession);
}

typedef  BOOL(__stdcall *FUN_CONNECTEX)(NET_SOCKET s, const struct sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped);

#define GUID_WSAID_CONNECTEX \
	{0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}

FUN_CONNECTEX get_connect_ex_fun(NET_SOCKET s)
{
	FUN_CONNECTEX lpfnConnectEx = 0;
	GUID guidConnectEx = GUID_WSAID_CONNECTEX;
	DWORD dwBytes = 0;
	WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidConnectEx, sizeof(guidConnectEx),
		&lpfnConnectEx, sizeof(lpfnConnectEx),
		&dwBytes, 0, 0
		);
	return lpfnConnectEx;
}

NET_API net_socket
net_connect(struct net_service* service, const char* ip, unsigned short port)
{
	NET_SOCKET s;
	struct net_session* session;
	struct connect_session* csession;
	ffid_vtype id;
	FUN_CONNECTEX connectExFun;
	int err;

	struct net_addr addr;
	struct net_addr addr_s;

	if(!ip || net_addr_help(&addr, ip, port, AF_UNSPEC, 0))
	{
		return 0;
	}
	
	if(net_addr_help(&addr_s, 0, 0, addr.ai_list->ai_family, AI_PASSIVE))
	{
		free_net_addr(&addr);
		return 0;
	}
	s = bind_help(service, addr_s.ai_list);
	free_net_addr(&addr_s);
	if(NET_INVALID_SOCKET == s)
	{
		return 0;
	}

	connectExFun = 0;
	connectExFun = get_connect_ex_fun(s);
	if(!connectExFun)
	{
		free_net_addr(&addr);
		net_close_fd(s);
		return 0;
	}

	csession = (struct connect_session*)malloc(sizeof(struct connect_session));
	if(!csession)
	{
		free_net_addr(&addr);
		net_close_fd(s);
		return 0;
	}
	memset(csession, 0, sizeof(struct connect_session));
	csession->s = s;

	session = create_net_session();
	if(!session)
	{
		free_net_addr(&addr);
		net_close_fd(s);
		release_connect_session(csession);
		return 0;
	}

	id = add_net_session(service, session);
	if(!id)
	{
		free_net_addr(&addr);
		net_close_fd(s);
		release_net_session(session);
		release_connect_session(csession);
		return 0;
	}

	csession->id = id;
	csession->op = OP_NET_CONNECT;

	session->connect_flag = 1;
	session->fd = s;
	session->data = 0;
	session->ai_family = addr.ai_list->ai_family;


	if(!connectExFun(s, addr.ai_list->ai_addr, (int)addr.ai_list->ai_addrlen,
		0, 0, (LPDWORD)&csession->send_bytes, (LPOVERLAPPED)&csession->overlapped))
	{
		err = net_get_error();
		if(err != ERROR_IO_PENDING)
		{
			free_net_addr(&addr);
			release_connect_session(csession);
			net_socket_close(service, id, 0);
			return 0;
		}
	}
	free_net_addr(&addr);
	return id;
}

NET_API int
net_wait(struct net_service* service, int timeout)
{
	int ret;
	int err;
	struct iocp_data* ov_data;
	PULONG_PTR data;
	DWORD bytes;
	int cnt;

#if _WIN32_WINNT >= _WIN32_WINNT_WIN6
	ULONG ulCount;
	ULONG ulNR;
	ULONG i;
	OVERLAPPED_ENTRY entries[32];

	cnt = 0;

	ulCount = sizeof(entries) / sizeof(OVERLAPPED_ENTRY);
	ulNR = 0;

	ov_data = 0;
	data = 0;
	bytes = 0;
	err = 0;
	{
		ret = GetQueuedCompletionStatusEx(service->net_service_fd, entries, ulCount, &ulNR, timeout, 0);
		err = net_get_error();
		if (err == WAIT_TIMEOUT)
		{
			err = 0;
		}
		if (!ret)
		{
			if (err)
			{
				return -err;
			}
			return cnt;
		}

		for (i = 0; i < ulNR; ++i)
		{
			ov_data = (struct iocp_data*)entries[i].lpOverlapped;
			bytes = entries[i].dwNumberOfBytesTransferred;
			if (ov_data)
			{
				switch(ov_data->op_type)
				{
				case OP_NET_ACCEPT:
					handle_accept(service, ret, err, (struct accept_session*)ov_data);
					break;
				case OP_NET_READ:
					handle_read(service, ret, err, (struct read_session*)ov_data, bytes);
					break;
				case OP_NET_WRITE:
					handle_write(service, ret, err, (struct write_session*)ov_data, bytes);
					break;
				case OP_NET_CONNECT:
					handle_connect(service, ret, err, (struct connect_session *)ov_data, bytes);
					break;
				}
			}
		}
		cnt += (int)ulNR;
	}
	return cnt;

#else
	cnt = 0;
	{
		ret = GetQueuedCompletionStatus(service->net_service_fd, &bytes, (PULONG_PTR) &data, (LPOVERLAPPED*)&ov_data, timeout);
		err = 0;
		if (!ret)
		{
			err = net_get_error();
		}

		if (err == WAIT_TIMEOUT)
		{
			err = 0;
		}
		if(!ov_data)
		{
			if(err)
			{
				return -err;
			}
			return cnt;
		}
		else
		{
			switch(ov_data->op_type)
			{
			case OP_NET_ACCEPT:
				handle_accept(service, ret, err, (struct accept_session*)ov_data);
				break;
			case OP_NET_READ:
				handle_read(service, ret, err, (struct read_session*)ov_data, bytes);
				break;
			case OP_NET_WRITE:
				handle_write(service, ret, err, (struct write_session*)ov_data, bytes);
				break;
			case OP_NET_CONNECT:
				handle_connect(service, ret, err, (struct connect_session *)ov_data, bytes);
				break;
			}
		}
		cnt += 1;
	}
	return cnt;
#endif
}

NET_API void
net_socket_close(struct net_service* service, net_socket nd, char send_rest)
{
	unsigned short index;
	struct net_session* session;

	if(!service)
	{
		return;
	}
	if(!nd)
	{
		return;
	}

	index = ffid_index(service->socket_ids, nd);
	net_lock(&service->session_lock[index]);
	session = service->sessions[index];
	if(!session || session->id != nd)
	{
		net_unlock(&service->session_lock[index]);
		return;
	}
	if(send_rest)
	{
		post_write(service, session);
	}

	service->sessions[index] = 0;

	if(session->wsession && session->wsession->op == OP_NET_WRITE)
	{
		shutdown(session->fd, 0);
		session->wsession->fd = session->fd;
		session->wsession->send_rest = send_rest;
	}
	else
	{
		shutdown(session->fd, SD_BOTH);
		net_close_fd(session->fd);
	}
	release_net_session(session);
	net_unlock(&service->session_lock[index]);

	net_lock(&service->id_lock);
	ffid_del_id(service->socket_ids, nd);
	net_unlock(&service->id_lock);
}




#endif

