程序中一共有两个read

![image-20210104210109671](https://static.hack1s.fun/images/2021/02/06/image-20210104210109671.png)

一个将内容读在了栈上，一个读在了bss段

第一次溢出只能溢出两个字，所以是一个栈迁移的题目

但是这个题比较烦人的地方在于bss段和got表特别接近

![image-20210104215804626](https://static.hack1s.fun/images/2021/02/06/image-20210104215804626.png)

如果直接用栈迁移的payload会导致在执行read的时候栈空间不够，导致got表被覆盖；

所以在迁移的指令开始增加一些ret作为滑板指令；

最后溢出的时候用system不行，要用execve

网上的exp都是用了one_gadget，但是做这个的时候没有发现附加有libc的链接，如果没有libc的链接还是蛮难搞的啊

另外还出现了本地打不通，远程能打通的情况