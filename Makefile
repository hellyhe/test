CFLAGS  += `pkg-config --cflags glib-2.0`
LDFLAGS += `pkg-config --libs glib-2.0`

#  gcc -lxml2 parse1.c -o bin/xml -I/usr/include/libxml2/ -lxml2
# C_INCLUDE_PATH=/usr/include/libxml2/ 在当前session中有效

# 可执行文件
TARGET = me
# 依赖目标
SRCS = mnet.c

OBJS = $(SRCS:.c=.o)

# 指令编译器和选项
CC=gcc
CFLAGS += -Wall -std=gnu99 -lpcap -lnet -g

$(TARGET):$(OBJS)
# @echo TARGET:$@
# @echo OBJECTS:$^
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(TARGET) $(OBJS)

%.o:%.c  
	$(CC) $(CFLAGS) -o $@ -c $<  
