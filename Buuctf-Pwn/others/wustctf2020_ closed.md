checksec

![image-20210411104119928](https://static.hack1s.fun/images/2021/04/10/image-20210411104119928.png)

IDA打开看到程序vuln中执行了

`close(1);close(2)`

关闭了stdout和stderr

之后直接返回了一个shell，也就是说这个连过去直接就是一个shell，并且也可以输入，但是没有回显

这里涉及到的就是输出的重定向

执行`exec 1>&0`将输出重定向到输入的socket中，就可以看到flag了

