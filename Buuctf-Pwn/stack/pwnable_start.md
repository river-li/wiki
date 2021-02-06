checksec会发现是一个安全机制全关的程序

![image-20201124212140407](https://static.hack1s.fun/images/2021/02/06/image-20201124212140407.png)

这个程序本身很短

![image-20201124211033313](https://static.hack1s.fun/images/2021/02/06/image-20201124211033313.png)

start部分就这么短

这里就调用了一个write，输出了0x14的字符，之后就read了0x3c的字符

这里在ret之前将esp+14h

也就是说在输入的这个位置就是返回值了

函数内容很短，并且因为没有开保护机制，可以考虑直接在栈上写shellcode ，那么问题就是怎么得到栈上的地址

可以在执行到要ret的时候将返回地址写成`mov ecx,esp`这个指令的地址，这样直接再执行一遍write

还没完全弄明白，等等继续