target = revert_superblock
objs = revert_superblock.o util.o

CC = gcc
CFLAGS = -Wall -g


.SUFFIXES: .c .o

target: $(objs)
	$(CC) -o $(target) $^


.c.o:
	$(CC) $(CFLAGS) -c $<


clean:
	rm $(target) $(objs)
