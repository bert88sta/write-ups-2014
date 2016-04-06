# Pico CTF 2014 : Hardcore ROP

**Category:** Master Challenge
**Points:** 200
**Description:**

>This program is obviously broken, but thanks to ASLR, PIE, and NX it's still pretty secure! Right?
NB: This problem is running in a slightly unusual setup to get extra PIE randomness. If you have an exploit that works 100% reliably locally (outside of GDB, which often disables any randomness), but you can't get it to land on our server, feel free to message us for help. [Source](hardcore_rop.c) [Binary](hardcore_rop)

>nc vuln2014.picoctf.com 4000

**Hint:**
>This is a statically linked binary (using musl libc). There is no full libc available for you to return into, but if you can leak a .text section address you can return into main(), randop(), and the chunks of libc that are included. Also, you'll probably need to hunt for ROP gadgets: here is a nice tool for that.

>[shell-storm.org](http://shell-storm.org/project/ROPgadget/)

## Write-up

Unfortunately for us, ASLR + PIE is very hard to beat. PIE does to the binary
what ASLR does to libc and the stack. There are no reliable PLT stubs, and no
GOT overwrites to be had here. NX negates any chance of shellcode at a random
address.  With that in mind, let's see the source:

```C
// PIE, NX, statically linked, with symbols.
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAPLEN (4096*10)

void randop() {
    munmap((void*)0x0F000000, MAPLEN);
    void *buf = mmap((void*)0x0F000000, MAPLEN, PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
    unsigned seed;
    if(read(0, &seed, 4) != 4) return;
    srand(seed);
    for(int i = 0; i < MAPLEN - 4; i+=3) {
        *(int *)&((char*)buf)[i] = rand();
        if(i%66 == 0) ((char*)buf)[i] = 0xc3;
    }
    mprotect(buf, MAPLEN, PROT_READ|PROT_EXEC);
    puts("ROP time!");
    fflush(stdout);
    size_t x, count = 0;
    do x = read(0, ((char*)&seed)+count, 555-count);
    while(x > 0 && (count += x) < 555 && ((char*)&seed)[count-1] != '\n');
}

int main(int argc, char *argv[]) {
    struct stat st;
    if(argc != 2 || chdir(argv[1]) != 0 || stat("./flag", &st) != 0) {
        puts("oops, problem set up wrong D:");
        fflush(stdout);
        return 1;
    } else {
        puts("yo, what's up?");
        alarm(30); sleep(1);
        randop();
        fflush(stdout);
        return 0;
    }
}
```
Briefly, everything important happens in `randop()`. The for loop generates us
some nice ROP gadgets based on the seed we provide to `srand()`. The important
thing about this is that with the same seed, the gadgets can relibably be
reporoduced. Furthermore, 0x0F000000 is the only reliable address we have in
this code.

If you're not familiar with a `syscall` then I'd suggest reaing up on them. In
order to get a `syscall`, we need a special instruction, namely `int 0x80;ret`.
This instruction gives us access to a few special functions. In order to find
the `int 0x80;ret` instruction, we'll need to make a script that tries
different seed values unti the instruction shows up. [My script](mem.py) is designed to
work with gdb-peda, but you could easily rework it for regular gdb :)

After running the script, I got a seed of "000L". Now let's find the offset for
hijacking `%eip`.

```
$ (python -c 'print "000L" + "a"*32 + "BBBB"' ) | strace ./hardcore_rop .
...
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x42424242} ---
```

The extra "." at the end is just to make sure the `chdir` conditional is
satisfied. You'll need that as an argument and also a file named "flag" in the same directory.
Now that we've gotten control, It's time to do the fun work with syscalls! :D

In order to get a shell to run, we need to get shellcode at 0x0f000000 
 (The only reliable address we have), change the privileges on it with `mprotect()`,
and jump there to execute it. In order to make this happen, we need to use our
special instruction to call `mprotect()` and `read()`. I'll say it again, go
read up on syscalls. If you still don't want to, here's the cliffnotes:

The `int 0x80` instruction is used to call all of the sycalls. When that
instruction runs, the number in `%eax` determines which syscall we get.
`mprotect()` needs eax to be 0x7d, and  `read()` needs to be 0x03. From there,
the arguments vary per syscall, but you should know that `%ebx`,`%ecx`, and
`%edx` contain the arguments (also `%esi` and `%edi` if it needs more than 3
arguments).

I like to use [KernelGrok's reference](http://syscalls.kernelgrok.com/) on
syscalls.

Either way, here is what we need:


opy to clipboard
|   syscall  |  eax |       ebx       |        ecx       |       edx       |
|:----------:|:----:|:---------------:|:----------------:|:---------------:|
| read()     | 0x03 | unsigned int fd | char __user *buf |   size_t count  |
| mprotect() | 0x7d |  unsigned long  |  startsize_t len | startsize_t len |
|            |      |                 |                  |                 |

## Other write-ups and resources

* <https://ctf-team.vulnhub.com/picoctf-2014-hardcore-rop/>
* <https://github.com/PizzaEaters/picoCTF-2014/tree/master/hardcore_rop>
* <http://barrebas.github.io/blog/2014/11/06/picoctf-hardcore-rop/>
* <https://www.whitehatters.academy/picoctf-hardcore-rop/>
