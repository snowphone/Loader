TARGETS=apager dpager
CPPFLAGS=
CFLAGS=-O2 -g  -DNDEBUG	-std=gnu99
#CFLAGS=-Og -g  -std=gnu99

all: $(TARGETS)

apager : main.o loader.o common.o
	$(CC) $^ -o $@

dpager : demand_main.o demand_loader.o common.o
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

demand_main.o: main.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DDEMAND -o $@ -c $<

clean:
	$(RM) $(TARGETS) $(patsubst %.c, %.i, $(wildcard *.c)) $(patsubst %.c, %.o, $(wildcard *.c))
