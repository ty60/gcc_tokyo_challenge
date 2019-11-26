CC=afl-gcc

all: strcmp.so


strcmp.so: strcmp.c strcmp.h
	$(CC) -o strcmp.so -shared strcmp.c
