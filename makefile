

MODE=32


CC= gcc -g -m$(MODE) -std=c11  -O0 -Wall -fmessage-length=0  -DATOMIC_C11 -fno-omit-frame-pointer
CPP= g++ -g -m$(MODE) -std=c++11 -DATOMIC_CPP11 -O0 -Wall -fmessage-length=0 -fno-omit-frame-pointer
CC := $(CPP)


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

libnet_service.a: $(O_FILES)
	ar rcs $@ $^

mingw:
	make libnet_service.a
	make test/clients.exe
	make test/server.exe

linux:
	make libnet_service.a
	make test/clients
	make test/server
	

.PHONY : clean
clean:
	rm -f $(O_FILES) libnet_service.a test/*.exe test/*.o  test/clients test/server
