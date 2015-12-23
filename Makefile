CFLAGS  += `pkg-config --cflags glib-2.0`
LDFLAGS += `pkg-config --libs glib-2.0`

# 可执行文件
TARGET = net302
# 依赖目标
SRCS = net302.c

OBJS = $(SRCS:.c=.o)

# 指令编译器和选项
CC=gcc
CFLAGS += -Wall -std=gnu99 -lpcap -lnet -g

$(TARGET):$(OBJS)
# @echo TARGET:$@
# @echo OBJECTS:$^
	$(CC) -o $@ $^

clean:
	rm -rf $(TARGET) $(OBJS)

%.o:%.c  
	$(CC) $(CFLAGS) -o $@ -c $<  
