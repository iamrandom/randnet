


#include <stdio.h>
#include <stdlib.h>
#include "../net/net_atomic.h"
#include "../net/buff.h"
#include "../net/net_service.h"

#include "pthread.h"


void*
thread_run(void* param)
{
	struct net_service* ns;
	ns = (struct net_service*)param;
	while(1)
	{
		net_wait(ns, 100);
	}
	
	return 0;
}

void handle_client_read(struct net_service* ns, net_socket nd, int v)
{
	char buff[1024];
	int ret;
	char* pMsg;

	

	if (v == RECV_BUFF_USE_QUEUE)
	{
		pMsg = 0;
		while((ret = net_socket_read(ns, nd, (void*)&pMsg, sizeof(pMsg))))
		{
			if(ret > 0)
			{
				pMsg[ret - 1] = 0;
				// printf("recv msg %s\n", pMsg);
				net_socket_write(ns, nd, pMsg, ret);
				free(pMsg);
			}
			else
			{
				// create lager buff，read again
				printf("recv error %d\n", ret);
				break;
			}
		}
	}
	else if(v == RECV_BUFF_USE_BUFF)
	{
		while((ret = net_socket_read(ns, nd, buff, sizeof(buff)/sizeof(buff[0]))) > 0)
		{
			if(ret < (int)(sizeof(buff)/sizeof(buff[0])) )
			{
				buff[ret - 1] = 0;
				// printf("recv msg %s\n", buff);
				net_socket_write(ns, nd, buff, ret);
			}
			else
			{
				// create lager buff，read again
				break;
			}
		}
	}
}

int main(int argc, char** argv)
{
	struct net_service* ns;
	pthread_t ts[2];
	struct net_event events[64];
	struct buff_pool* pool;
	int i;
	int ret;
	void* status;
	unsigned int e;
	net_socket nd;
	struct net_config cfg;
	int count;
	int v;

	pool = buff_pool_create(1024, 64);
	if(!pool)
	{
		printf("buff_pool_create faild\n");
		exit(-1);
	}

	ns = net_create(1024 * 8);
	if(!ns)
	{
		printf("open net_service faild\n");
		exit(-1);
	}

	nd = net_listen(ns, 9524, 64);
	if(nd == 0)
	{
		printf("listen faild\n");
		exit(-1);
	}

	for(i = 0; i < (int)(sizeof(ts)/sizeof(ts[0])); ++i)
	{
		pthread_create(ts + i, 0, thread_run, ns);
	}

	count = 0;

	v = RECV_BUFF_USE_QUEUE;


	while(1)
	{
		// net_wait(ns, 100);
		ret = net_queue(ns, events, sizeof(events)/sizeof(events[0]));
		if(ret < 0)
		{
			break;
		}
		if(ret == 0)
		{
			net_thread_sleep(10);
			++count;
			printf("-------------------------------- %d \n", net_socket_size(ns));
			fflush(stdout);
			if(count % 100 == 0)
			{				
			}
			continue;
		}

		for(i = 0; i < ret; ++i)
		{
			e = events[i].events;
			if(e & Eve_Accept)
			{
				// a new client
				while(( nd = net_accept(ns, events[i].nd) ) )
				{
					cfg.enByte = enByte16;
					cfg.read_buff_cnt = 8;
					cfg.write_buff_cnt = 8;
					cfg.pool = pool;
					cfg.read_buff_version = v;

					if(net_socket_cfg(ns, nd, &cfg) < 0)
					{
						net_socket_close(ns, nd, 0);
					}
					else
					{
						// add a client
						// printf("recv one session %d \n", nd);
						// fflush(stdout);
					}
				}
				continue;
			}

			if(e & Eve_Error)
			{
				printf("socket close %d\n", events[i].nd);
				fflush(stdout);
				net_socket_close(ns, events[i].nd, 0);
				continue;
			}
			
			if(e & Eve_Read)
			{

				handle_client_read(ns, events[i].nd, v);
			}
		}

	}

	for(i = 0; i < (int)(sizeof(ts)/sizeof(ts[0])); ++i)
	{
		pthread_join(ts[i], &status);
	}
	net_close(ns);
	buff_pool_release(pool);
	return 0;
}


