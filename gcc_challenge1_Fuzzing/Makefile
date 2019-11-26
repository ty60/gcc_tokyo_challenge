PROGS = simple_linter simple_linter-afl


all: $(PROGS)


simple_linter: simple_linter.c
	gcc -o simple_linter simple_linter.c

simple_linter-afl: simple_linter.c
	afl-gcc -o simple_linter-afl simple_linter.c


clean:
	rm $(PROGS)
