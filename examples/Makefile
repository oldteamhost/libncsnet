CC := cc
CFLAGS := -Wall -O3 -I../ -g
LDFLAGS := -L../ -Wl,-rpath,../
LDLIBS := -lncsnet

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
PROGS := $(SRCS:.c=)

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(PROGS) $(OBJS)
