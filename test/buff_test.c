#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>

#include "../net/buff.h"


int main(int argc, char** argv)
{

	struct recv_buff* rbuff;
	struct send_buff* sbuff;
	struct buff_pool* pool;
	void * pdata;
	void * pdata2;
	size_t st;
	size_t st2;
	char msg[] = "hello random fsdaflkdsjfklsdlkafjlkdslkfjldsjfldjslfjlsdjalfjdlsajfldsjlafjldsjla";
	char buff[1024];
	char* pMsg;
	int msg_len;
	int i, j, buff_len;

	srand((unsigned)time(NULL));

	pool = buff_pool_create(128, 31);

	rbuff = recv_buff_create(enByte16, 16, pool, RECV_BUFF_USE_QUEUE);
	sbuff = send_buff_create(enByte16, 16, pool);

	for(i = 0; i < 4000; ++i)
	{

		printf("%d++++++++++++++++++++++++++++++++++++\n", i);
		for(j = 0; j < rand()%8; ++j)
		{
			sprintf(buff, "hello %d %d random %d %d %d end", i, j, rand(), rand()*rand(), rand()*rand()*rand());
			buff_len = strlen(buff);
			buff[buff_len] = 0;
			if( send_buff_write(sbuff, buff,  buff_len + 1)  == (buff_len + 1))
			{
				printf("send ------------%d----%s--------\n",  buff_len + 1, buff);
			}
			else
			{
				printf("send faild\n");
			}
			
		}


		while((st = send_buff_prepare(sbuff, &pdata)))
		{
			st2 = recv_buff_prepare(rbuff, &pdata2);
			
			if(st2 >= st)
			{
				memcpy(pdata2, pdata, st);
				recv_buff_consume(rbuff, st);
				send_buff_consume(sbuff, st);
			}
			else
			{
				memcpy(pdata2, pdata, st2);
				recv_buff_consume(rbuff, st2);
				send_buff_consume(sbuff, st2);
			}
			if(st2 < 0)
			{
				printf("error        st2 < 0");
				return -1;
			}
			if(st2 == 0)
			{
				break;
			}
		}
				for(j = 0; j < (rand()%8); ++j)
		{
			pMsg = 0;
			msg_len = recv_buff_read(rbuff, (void*)&pMsg, sizeof(pMsg));
			if(msg_len <= 0){				
				break;
			} 
			printf("recv ------------%d-----%s-------\n", msg_len, pMsg);
			free(pMsg);
		}

	
	}
	
	// msg_len = recv_buff_read(rbuff, buff, sizeof(buff));
	// buff[msg_len] = 0;
	// printf("------------%d %s------------\n", msg_len, buff);



	recv_buff_release(rbuff);
	send_buff_release(sbuff);

	return 0;
}