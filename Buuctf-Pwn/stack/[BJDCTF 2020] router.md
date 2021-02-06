检查安全机制发现是64位程序

![image-20201218150055017](https://static.hack1s.fun/images/2021/02/06/image-20201218150055017.png)

程序主要是一个循环

![image-20201218153400218](https://static.hack1s.fun/images/2021/02/06/image-20201218153400218.png)

其中只有前三个case有用，后面几个都没有什么用

这里发现case1是存在了一个system

这里可能是我们最后想要利用的地方，dest这个原本是一个字符串

内容可以用p64来读

![image-20201218154228878](https://static.hack1s.fun/images/2021/02/06/image-20201218154228878.png)

就是一个ping

这里有可能是有命令执行的，直接尝试一下，输入`;cat flag`就成了