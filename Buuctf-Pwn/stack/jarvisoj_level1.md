checksec

![image-20201218160559651](https://static.hack1s.fun/images/2021/02/06/image-20201218160559651.png)

这个题目也不知道为啥在这么靠后的位置，蛮简单的

![image-20201218160718134](https://static.hack1s.fun/images/2021/02/06/image-20201218160718134.png)

还给输出了buf的基地址，这是想让直接在栈上写shell

但是这个程序远程又不是直接给输出的，还必须要send之后才有回复

所以还是要用rop来做，shellcode直接用level3就可以