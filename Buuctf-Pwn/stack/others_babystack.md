程序开启了NX、RELRO和CANARY

![image-20210106212727029](https://static.hack1s.fun/images/2021/02/06/image-20210106212727029.png)



这个程序运行是一个菜单，1输入2输出3退出

![image-20210106212609606](https://static.hack1s.fun/images/2021/02/06/image-20210106212609606.png)

这个输入部分存在0x100-0x90=0x70的溢出

注意！！这里不是只有0x10

每次遇到这种16进制运算都容易弄错；

因为存在CANARY，所以溢出之前首先要得到Canary的值

rbp在0x90的位置，那么canary就在这下面0x8，就是偏移0x88的位置

所以先用puts输出一次canary，之后在构造栈来溢出



思路是这样蛮顺畅的，但不知道为什么就是跑不通，等一段时间看

【未完成】