

TARGET=apager
OBJS:=$(patsubst %.c, %.o, $(wildcard *.c))

$(TARGET) : $(OBJS)
	$(CC) $^ -o $@

%.o: %.c
	$(CC) -g -O0 -c $<

clean:
	$(RM) $(TARGET) *.o
