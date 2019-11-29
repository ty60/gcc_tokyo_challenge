PROGS = simple_linter simple_linter-afl simple_linter_strcmp-afl simple_linter_laf-intel


all: $(PROGS)

simple_linter: simple_linter.c
	gcc -o simple_linter simple_linter.c

simple_linter-afl: simple_linter.c
	afl-gcc -o simple_linter-afl simple_linter.c

simple_linter_strcmp-afl: simple_linter_strcmp.c
	afl-gcc -o simple_linter_strcmp-afl simple_linter_strcmp.c

simple_linter_laf-intel: simple_linter_strcmp.c
	afl-clang-fast -o simple_linter_laf-intel simple_linter.c

clean:
	rm $(PROGS)
