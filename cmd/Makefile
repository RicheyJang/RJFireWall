TARGET := uapp
INCLUDES := -I. -Iinclude
SRCS = kernel.c main.c exchange.c
CC := gcc
OBJS = $(SRCS:.c=.o)

$(TARGET):$(OBJS)
	$(CC) -o $@ $^
	rm -rf $(SRCS:.c=.o)
%.o:%.c
	$(CC) $(INCLUDES) -o $@ -c $<

install:
	mv $(TARGET) ..

clean:
	rm -rf $(basename $(TARGET)) $(SRCS:.c=.o)