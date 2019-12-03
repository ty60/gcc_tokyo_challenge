targets = revert_superblock list_superblock_xid revert_old_superblock

CC = gcc
CFLAGS = -Wall -g


.SUFFIXES: .c .o

all: $(targets)

revert_superblock: revert_superblock.o apfs.o util.o
	$(CC) -o revert_superblock $^

list_superblock_xid: list_superblock_xid.o apfs.o util.o
	$(CC) -o list_superblock_xid $^

revert_old_superblock: revert_old_superblock.o apfs.o util.o
	$(CC) -o revert_old_superblock $^

.c.o:
	$(CC) $(CFLAGS) -c $<


clean:
	rm -f $(targets) *.o
