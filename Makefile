

TARGET=main

$(TARGET) : main.o
	$(CC) $^ -o $@

%.o: %.c
	$(CC) -g -O0 -c $<

clean:
	$(RM) $(TARGET) *.o
