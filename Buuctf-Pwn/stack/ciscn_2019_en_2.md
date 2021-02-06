首先checksec检查安全机制

![image-20200625194857123](https://static.hack1s.fun/images/2021/02/06/image-20200625194857123.png)

同样是开启了NX的程序

可能也是一道ROP的题目

看了逆向的代码之后发现和`ciscn_2019_c_1`几乎一样，两道题目唯一的区别就是之前那个题附带给了libc，这个题没有给libc的文件

所以主要改的地方就是libc的利用这里

从原本的直接读本地libc，改成利用`LibcSearcher`

两道题目甚至可以用同一个exp