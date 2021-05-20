USENIX2021，奇安信、上交、清华一起的论文

Sharing More and Checking Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems



## TL;DR

提出了一个静态污点分析的方法

实现了一个原型，Shared-keyword aware Taint Checking;

在39个固件中发现了33个bug，其中30个分配了CVE/CNVD/PSV

核心的假设观点为：固件中Web接口显示的字符串应该是在前后端公用的

即，前端接收看到的字符串，在后端处理这个字符串的相应位置也会有对应的字符串出现；



所以可以通过这种方法通过前端的字符串，定位到后端的处理程序；

通过这样的方法可以利用静态分析从前端直接联系到后端，克服了静态分析难以联系多个文件的缺陷；



## Introduction

在手动挖掘漏洞的过程中，观察到一个事实：发现漏洞的关键是定位前端web服务的数据传输到后端处理用户输入的代码

![image-20210428111710691](https://static.hack1s.fun/images/2021/05/06/image-20210428111710691.png)

作者团队的观点在于：后端用于处理用户输入的函数通常与相应的前端文件使用相似的关键词。前端中用户输入被一个关键词labeled并编码，在后端则使用同样的关键词来提取从前端传输过来的用户输入；

为了提高检测漏洞的速度，文章提出了三个相比于传统污点分析技巧的优化：

- 基于Firmware的特点，开发了一个粗力度的污点引擎，这个引擎包含了一些针对特定函数的规则，其中做了一些效率和准确度之间的取舍；
- 通过input guidance和trace merging加速污点分析path exploration的过程；
- 最终针对特殊函数中的路径爆炸，使用了一个优先级算法保证执行有效性；



整个系统实现了三个组件：

- 输入关键词的提取器，用来从前端文件中提取出关键词；
- 后端输入的入口点识别器，用来定位输入entry在后台二进制中的位置；
- 一个输入敏感的污点分析引擎，用来检测漏洞；

整个系统是基于Ghidra和KARONTE实现的；

文章说之后会把代码和数据开源，可以蹲一手

https://github.com/NSSL-SJTU/SaTC



## Problem and Approach

文章的基本威胁模型如下

针对的对象：路由器和Web摄像头；

攻击者的能力：能够获取固件，但无法物理接触到设备，仅能够通过前端访问到设备；

设备的防护能力：后端程序开启了NX、Canary、ASLR等state-of-art的防护机制，但是受资源影响不存在SDN、IDS等系统；



现有的动态分析方案主要思路是Fuzzing或是Emulation，主要有这样几个工作

- Firmadyne
- FirmAE
- FirmAFL
- IOTFuzzer
- SRFuzzer
- Avatar

但是这些动态Fuzz的方法缺陷在于，Fuzz前如果堆路由器没有足够多的知识，以及人为的操作究竟是什么样的，动态运行的方法有可能会错过一些高危的漏洞；

而静态分析的工具，例如KARONTE，主要是关注后端的二进制程序，例如KARONTE是检测程序中的IPC，通过这些分析跨二进制的漏洞。但是随着分析的过程，IPC接口数量增加会带来许多False Postive。因此需要识别出真正可以从前端传入的输入在后端的位置，对其进行更准确的分析。



典型的示例流程：

- 在前端的js、html等文件中发现关键词；
- 通过这个关键词定位到后端处理的地方；
- 从这个地方开始标记为污点开始进行传播；



关于污点分析的几篇文章：

- [2005 NDSS] Dynamic Taint Analysis for Automatic Detection, Analysis, and SignatureGeneration of Ex- ploits on Commodity Software.
- [2010 S&P] All You Ever Wanted to Know About Dynamic Taint Analysis and Forward Symbolic Execution (But Might Have Been Afraid to Ask).
- [2009 Sigplan Notice] TAJ: Effective Taint Analysis of Web Applications.



作者团队在做大规模的实验前经过了手动分析的验证，手工分析了10个路由器的固件；

主要过程包括下面三步：

- 选择前端的字符串，手动发送很多请求；
- 手动在后端利用专家知识筛选例如`websGetVar`这样的函数调用的地方，筛出来这些字符串；
- 取前两者的交集，变异前端请求，观察后端收到的数据是否会发生变化；



验证了这一猜想的有效性之后，就是整篇文章关键需要解决的几个问题；

1. 识别前端的关键词；
2. 定位后端处理输入的handler；
3. 跟踪用户输入的流向，用来识别漏洞；



### 识别前端关键词

乍一看这个工作应该很容易，但是实际上在一个固件中有很多的前端文件，每一个文件中又有很多这样的字符串关键词，在没有专家知识的前提下筛选合适的关键词是比较麻烦的；





### 定位后端handler

后端文件函数有很多，但只有一小部分是用来处理前端的输入的

同前一个问题，后端程序也含有大量的字符串，因此准确识别出处理函数的位置也是一个困难的工作；





### 污点分析

静态工具（KARONTE、Angr）的能力都比较有限，文中说法是

> Unfortunately, the state-of-the-art analysis tools [34, 38] introduce high overhead, and cannot handle the elaborate control-flow graph or bypass the user- input sanitization. 

所以就做了一个自己实现的污点分析工具；

![image-20210428190106369](https://static.hack1s.fun/images/2021/05/06/image-20210428190106369.png)

