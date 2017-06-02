

MODE?=64


CC= gcc -m$(MODE) -std=c11 -o2  -O0 -Wall -fmessage-length=0  -fno-omit-frame-pointer
CPP= g++ -m$(MODE) -std=c++11 -o2 -O0 -Wall -fmessage-length=0 -fno-omit-frame-pointer
DFLAG?=
CC := $(CPP) $(DFLAG)


SRC_PATH = tool:net
INCLUDE =

C_SRC_FILES = $(foreach dd,$(subst :, ,$(SRC_PATH)),$(wildcard $(dd)/*.c))
O_FILES = $(foreach dd, $(C_SRC_FILES), $(subst .c,.o,$(dd)))


%.o:%.c
	$(CC) -c $^ -o $@ $(INCLUDE)

%.exe:  %.o
	$(CC)  -o $@ $^  -L.  -lnet_service -lws2_32 -lmswsock -lpthread

test/clients: $(O_FILES) test/clients.o
	$(CC) $^ -o $@ -L. -lnet_service -ldl -lrt  -lpthread

test/server: $(O_FILES) test/server.o
	$(CC) $^ -o $@  -L. -lnet_service -ldl -lrt -lpthread

test/epoll_test:test/epoll_test.o
	$(CC) $^ -o $@  -L. -ldl -lrt -lpthread

test/epoll_test_client:test/epoll_test_client.o
	$(CC) $^ -o $@  -L. -ldl -lrt

test/ipv6_test.exe:test/ipv6_test.o
	$(CC)  -o $@ $^  -lws2_32 -lmswsock

test/ipv6_test2:test/ipv6_test2.o
	$(CC)  -o $@ $^  -ldl -lrt 

test/ipv6_test3:test/ipv6_test3.o
	$(CC)  -o $@ $^  -ldl -lrt 

libnet_service.a: $(O_FILES)
	ar rcs $@ $^



test/buff_test.exe:test/buff_test.o net/buff.o net/buff_pool.o
	$(CC)  -o $@ $^ 


mingw:
	make libnet_service.a DFLAG="-D_WIN32_WINNT=_WIN32_WINNT_WINXP"
	make test/clients.exe DFLAG="-D_WIN32_WINNT=_WIN32_WINNT_WINXP"
	make test/server.exe  DFLAG="-D_WIN32_WINNT=_WIN32_WINNT_WINXP"

linux:
	make libnet_service.a
	make test/clients
	make test/server

.PHONY : clean_mingw
clean_mingw:
	rm -f $(O_FILES) libnet_service.a test/*.exe test/*.o  test/epoll_test test/ipv6_test.exe

.PHONY : clean_linux
clean_linux:
	rm -f $(O_FILES) libnet_service.a  test/*.o  test/clients test/server test/epoll_test  test/ipv6_test3 test/ipv6_test2

.PHONY : clean
clean:
	rm -f $(O_FILES) libnet_service.a test/*.exe test/*.o  test/clients test/server test/epoll_test test/ipv6_test3 test/ipv6_test2
