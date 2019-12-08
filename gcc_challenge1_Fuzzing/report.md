# Fuzzing report
I will explain not only my implementation to solve this task, but also my thinking process in much detail as possible.

## Program analysis
First I had a look at the distributed source code, `simple_linter.c`. From the observation, I interpreted that the goal of this task is to find the input which will make the program call the function `crash`. This function will access unmapped memory (`*((unsigned int *)1) = 1;`) resulting in a segmentation fault.

In the following sections, I will answer the questions asked in `README.md`.

## 1. AFL and laf-intel
### AFL
After installing AFL and compiling `simple_linter.c` with `afl-gcc`, I ran `afl-fuzz` for 24 hours on a virtual machine on ESXi, with 4 virtual CPUs and 8 GB of memory. The initial input queue was a single file containing a single byte ('A'). 
As a result, AFL was able to find two crashes, id: 0 and id: 2.

The crash inputs obtained are here: https://github.com/yasm1/gcc_tokyo_challenge/tree/master/gcc_challenge1_Fuzzing/out_dir_short/crashes

### laf-intel
I fuzzed `simple_linter.c` with laf-intel with the same setup as above.
When compiling `simple_linter.c` with laf-intel, the `LAF_TRANSFORM_COMPARES=1` was set to enable transform-compares pass functionality, which will expand strcmp using LLVM pass.
As a result, laf-intel was able to find three crashes, id: 0, id: 1 and id:2.
Since laf-intel is an extension of AFL, it is not surprising that it found crashes, id: 0 and id: 2. However, it is worth noting that laf-intel found crash id: 1, which is a crash that AFL was not able to trigger on its own.

The crash inputs obtained are here:
https://github.com/yasm1/gcc_tokyo_challenge/tree/master/gcc_challenge1_Fuzzing/out_dir_short_laf-intel/crashes

### Difference between AFL and laf-intel
The most outstanding difference between AFL and laf-intel is that AFL only found 2 crashes (id: 0, 2), whereas laf-intel found 3 crashes (id: 0, 1, 2). So AFL missed crash id: 1, but laf-intel was able to find it.

For `simple_linter.c` to crash with id: 1, the input file has to start with `"MAGICHDR"` to pass strcmp check at line 47. So the fuzzer has to somehow generate `"MAGICHDR"` to cause the crash with id: 1.
From the results, I was able to observe that AFL was not able to generate the `"MAGICHDR"` and laf-intel was able to.

AFL on its own is not good at passing a check like this using strcmp.

One reason for this is simply because the strcmp function in libc is not instrumented by the AFL compiler. AFL measures the coverage of a binary by executing instrumented instructions, inserted during the compilation of the program.
Since libc, which contains the strcmp function, is not instrumented by AFL compiler, AFL can not measure the coverage of the strcmp function. Hence AFL can not generate effective input to cover the strcmp function.

Even if strcmp is instrumented by the AFL compiler, there is another reason for AFL to fail to find an input that will pass the strcmp check.
The reason is that the strcmp function is a function which continues executing a loop, comparing one byte at a time.

AFL evolves the input queue by mutating inputs contained in the input queue. Mutated inputs that produce an executing trace containing newly observed jumps (tuples), or inputs that significantly increases the number of times the tuple is taken (hit count), will be added to the input queue for further mutation.
Hit counts are divided into several buckets (1, 2, 3, 4-7, 8-15, ..., 128+). If the mutated input causes a transition from one bucket to another, the input will be considered interesting and will be added to the input queue.
In strcmp there is a loop that contains a jump from the end of the loop to the beginning of the loop. So for AFL to crack the strcmp check, AFL has to continue generating inputs that cause transition of the hit count of the jump at the end of the loop, from one bucket to another, until the program crashes.

Looking at the given program (`simple_linter.c`) the string that the user input is compared to (`"MAGICHDR"`) is 9 bytes long (including the NULL byte at the end). AFL may cause bucket transition of strcmp, from bucket 1 to 2, from bucket 2 to 3 and bucket 3 to 4-7. However, it is unlikely to cause bucket transition from bucket 4-7 to 8-15 and trigger a crash.
For the transition from bucket 4-7 to 8-15 to happen, AFL has to guess 4 bytes of `"MAGICHDR"` in a single mutation, which is unlikely to happen.
So if strcmp is instrumented, it is likely for AFL to generate the first 4 bytes (`"MAGI"`), but not the remaining bytes (`"CHDR"`).

On the other hand, laf-intel was able to crack the strcmp check and trigger crash id: 1. This is because laf-intel separates strcmp function into number of single byte comparisons. For instance, `if (strcmp(input, "AB") == 0)` will be separated into 2 single byte comparisons like, `if (input[0] == 'A')  { if (input[1] == 'B') }`.
As explained above, the root cause of AFL not being able to crack strcmp check was because of the strcmp's loop structure. By splitting strcmp into separate single byte comparisons, there will be no more loop structure and AFL will be able to crack the `"MAGICHDR"` check.
In the given program (`simple_linter.c`), `if (strcmp(buf, "MAGICHDR") == 0)` will be separated into 9 single byte comparisons, which AFL should have no problem cracking (laf-intel is an extension of AFL).

## 2. angr
Source of the angr script can be seen here: https://github.com/yasm1/gcc_tokyo_challenge/blob/master/gcc_challenge1_Fuzzing/crack.py.
Crash inputs generated by the script can be found here:
https://github.com/yasm1/gcc_tokyo_challenge/tree/master/gcc_challenge1_Fuzzing/angr_crashes

My first thought for this quiz was to write a script using angr's `simgr.explore()` method to simply find inputs that will reach the `crash` function, like a typical CTF crackme challenge.
Although this script may generate an input that will make the program call `crash` and result in a segmentation fault, the implemented script will be looking for INPUTS THAT WILL CALL THE FUNCTION NAMED CRASH, instead of looking for INPUTS THAT WILL CRASH THE PROGRAM.

So I decided to enable angr's `STRICT_PAGE_ACCESS` option, which will tell angr's execution engine to raise SimSegFaultException when attempting to access memory address which is not permitted.

From the program analysis, I knew that `simple_linter.c` doesn't have so many `if` branches and `for`, `while` loop. So it seemed that simply symbolically executing the program from the beginning to the end with `simgr.run()` will find all the states where segmentation faults occurred. If the program was more complex, there would have been a possibility of path explosion. If this happens, it is likely that `simgr.run()` will not return.

However, by implementing this method and running it, I realized that SimProcedure of `fopen` attempts unpermitted memory access and raise SimSegFaultException. This will make angr's symbolic execution stop inside `fopen`.
This prevented the execution to reach states where the `crash` function causes a segmentation fault.

To solve this problem I decided to hook the problematic function, (`fopen` in this case).
In the hook, the `STRICT_PAGE_ACCESS` will be temporarily disabled, so the problematic function (`fopen`) will have no problem accessing unmapped memory region. Then, when the function (`fopen`) returns, the `STRICT_PAGE_ACCESS` will be enabled again.
By applying this hook to `fopen`, when `fopen` is called, `STRICT_PAGE_ACCESS` will be disabled. So there will be no SimSegFaultException raised which will stop the symbolic execution inside `fopen`.

After applying the method to `fopen`, I simply called `simgr.run()` which found crash states for id: 0, id: 1 and id: 2. Using crash states' `solver.eval` I was able to obtain the inputs that caused the crash.

## 3. AFL, angr and Driller
Symbolic executions do not always work better than fuzzing in the context of vulnerability finding. In the following paragraphs, I will explain the reason.

Before explaining the reason, I would like to introduce some terms which I will use in the answer.

Driller introduced the idea of general input and specific input, and it categorizes user inputs into one of the two input types.
General input is an input that has a wide range of valid values, whereas specific input is an input that has a limited set of valid values.
For instance, a user name is a general input and a magic number of a certain file type is a specific input.

I will answer the questions borrowing these terms (general and specific input) introduced by Driller.

### AFL
The advantage of fuzzers, such as AFL, is that it can quickly generate many general inputs to test the binary. Since AFL conducts minimal instrumentation on the target binary to measure the coverage, the overhead to test an input is small.

The disadvantage of AFL is that, since the mutation of the input to the binary is format-agnostic, it is unlikely for AFL to generate specific inputs. For example, it will be challenging for AFL to fuzz a config file parser, which frequently checks whether the provided config file contains correct config directive names. 

Overall, AFL can be a powerful tool to fuzz a program which handles generic inputs, but not so powerful when fuzzing a program that requires specific inputs.

### angr
The advantage of angr is that, by utilizing its constraint-solving engine, it can generate specific input for a given program.
Since angr is a concolic execution library, when executing a program, angr will add constraints to the user input until the program reaches a crash state. If the program reaches a crash state, then angr can perform constraint resolution to identify user input that will cause the program to crash.
This method can successfully obtain specific inputs (such as magic numbers) that are required for the program to crash.

One major disadvantage of angr is path explosion. When angr's execution engine encounters a conditional branch that depends on symbolic values, angr forks the path to explore both paths. The path that took the conditional branch and the path that did not take the conditional branch.
This behavior is one of the reasons why angr can recover specific inputs. But at the same time, this behavior will increase the number of paths in an exponential manner, so too many conditional branches could lead to path explosion.
Exploring multiple numbers of paths is time-consuming and path explosion will make angr's binary exploration impossible to finish in a reasonable amount of time.

Angr can be useful to analyze, explore and find specific inputs of a simple binary without too many conditional branches. On the other hand, using angr to generate many general inputs is possible, but can be time-consuming.

### Driller
Driller is a fuzzing tool that combines AFL and angr. Driller aims to use AFL to quickly generate many general inputs and use angr to generate specific inputs when required.

Ideally, Driller inherits the advantages of both AFL and angr. That is, the ability to quickly generate many general inputs like AFL and the ability to generate specific inputs like angr.
At the same time, this will mutually mitigate the disadvantages of AFL and angr. AFL's inability to generate specific input will be covered by angr, and angr's inability to generate many general inputs will be covered by AFL.

However, the disadvantages that are inherited from AFL and angr cannot be removed completely. For example, in Driller, AFL is used so that angr will not have to explore paths that can be explored by general inputs. This will greatly reduce the number of paths angr has to explore and save time for Driller.
Even though, the angr component of Driller is still time-consuming and requires enough amount of machine resources for concolic execution and constraint solving.

### Conclusion
From the discussion above, I conclude that symbolic execution (angr) is not always better than fuzzing (AFL) in the context of vulnerability finding.
AFL can be a powerful tool to generate general inputs and at the same time, angr can also be a powerful tool to generate specific inputs.
For the given program (`simple_linter.c`), angr was able to find three crashes, whereas AFL was only able to find two crashes. This is not because angr is always better at finding crashes, but because angr is better at generating specific inputs to pass complex checks, like the `strcmp(buf, "MAGICHDR")` check.
