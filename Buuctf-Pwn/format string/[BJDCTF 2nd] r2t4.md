首先checksec

![image-20201124205504272](https://static.hack1s.fun/images/2021/02/06/image-20201124205504272.png)

程序很少见的增加了canary

用IDA 64 打开

main函数

![image-20201124205623122](https://static.hack1s.fun/images/2021/02/06/image-20201124205623122.png)

这里溢出的字节很有限，只能溢出8个字节，这正好碰到了canary

没办法控制返回地址和rbp

注意到这个printf，很有意思，那这显然是一个格式化字符串的漏洞利用了

程序中有一个这样的backdoor函数

![image-20201124205604958](https://static.hack1s.fun/images/2021/02/06/image-20201124205604958.png)

暂时放一放，格式化字符串漏洞还没细看