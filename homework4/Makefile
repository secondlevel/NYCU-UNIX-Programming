CC = gcc
CXX = g++
CFLAGS	= -Wall -g
LDFLAGS = -lcapstone

PROGS = hw4

all: $(PROGS)

%: %.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $< $(LDFLAGS)

clean:
	rm -f -r $(PROGS) *.dSYM