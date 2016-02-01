

MODE=64


CC= gcc -g -m$(MODE) -std=c11  -O0 -Wall -fmessage-length=0  -DATOMIC_C11 -fno-omit-frame-pointer
CPP= g++ -g -m$(MODE) -std=c++11 -DATOMIC_CPP11 -O0 -Wall -fmessage-length=0 -fno-omit-frame-pointer
CC := $(CPP)


SRC_PATH = tool:net
INCLUDE =
LIB = 

C_SRC_FILES = $(foreach dd,$(subst :, ,$(SRC_PATH)),$(wildcard $(dd)/*.c))
O_FILES = $(foreach dd, $(C_SRC_FILES), $(subst .c,.o,$(dd)))


%.o:%.c
	$(CC) -c $^ -o $@ $(INCLUDE)

%.exe:  $(O_FILES) %.o
	$(CC) $^ -o $@  $(LIB)

test/clients: $(O_FILES) test/clients.o
	$(CC) $^ -o $@  $(LIB)

test/server: $(O_FILES) test/server.o
	$(CC) $^ -o $@  $(LIB)

mingw:
	make LIB=" -lws2_32 -lmswsock  "  test/clients.exe test/server.exe

linux:
	make LIB="  -ldl -lrt  "  test/clients test/server
	

.PHONY : clean
clean:
	rm -f $(O_FILES)
	rm -f test/*.exe test/*.o  test/clients test/server