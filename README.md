# Loader
It is a user-level implementation of `evecve` system call.
Any statically linked programs can be loaded.
Plus, it can load multiple programs at once.

## Build
To build, follow the instructions
```
cmake .
make
```
After building the project, you'll see `apager` and `dpager`.
Both have same interface and emit same results, but apager loads
programs all-at-once and dpager loads programs with demand-paging policy.

If you need some statically linked test programs, extract `test_examples.tgz` and
execute `build_examples.py`.

## Usage
First, you can run a single program.
```
./[apager/dpager] <program1> [<other_programs>...]
```
## How it works
Basically, apager and dpager read ELF header of a program and load segments,
	a collection of sections, and jump to entry point for each program.
The difference of pagers is the way a pager loads segments to memory.
Apager loads whole needed segments at once.
In contrast, dpager only loads each page of a program when the process catch
page fault by analyzing ucontext variable and get a page fault address.

Apager and dpager use `ucontext` header to context switch between loader and loadee.
Before switching, a loader create additional stack for a loadee process.
The stack contains argc, argv, envp and auxv.
After that, it creates new context with entry point and its own stack.
Normally, statically linked program's entry point is located at 0x400A30.
Finally, jump to the entry point by calling `swap_context`.

To execute a series of programs, a loader needs to switch back from a loadee to
the loader.
Executing the entry point, RDX register value is used as `rtld_fini` function address
, which is one of exit handlers.
And `rtld\_fini` is normally assigned to NULL.
So, in this project switching back procedure is implemented by exploiting `rtld_fini`.

