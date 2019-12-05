TARGET=apager
OBJS:=$(patsubst %.c, %.o, $(wildcard *.c))
CPPFLAGS=
CFLAGS=-Og -g 

$(TARGET) : $(OBJS)
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

clean:
	$(RM) $(TARGET) $(OBJS) $(patsubst %.c, %.i, $(wildcard *.c))
