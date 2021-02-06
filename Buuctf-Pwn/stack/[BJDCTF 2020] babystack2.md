首先checksec

![image-20201202153827176](https://static.hack1s.fun/images/2021/02/06/image-20201202153827176.png)

发现是64位程序

![image-20201202153955291](https://static.hack1s.fun/images/2021/02/06/image-20201202153955291.png)

main函数首先输入了一个长度，之后用read读了这个长度的内容

感觉是整形溢出

另外还存在一个backdoor

![image-20201202154037653](https://static.hack1s.fun/images/2021/02/06/image-20201202154037653.png)

很简单，长度输入-1绕过之后直接返回到backdoor就完了

脚本就不贴了