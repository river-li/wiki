checksec发现

![image-20201218183037735](https://static.hack1s.fun/images/2021/02/06/image-20201218183037735.png)

main函数

![image-20201218185132186](https://static.hack1s.fun/images/2021/02/06/image-20201218185132186.png)

v4这里可以导致溢出

scanf需要调试着来确定偏移，发现返回地址在偏移24的位置

之后直接返回到后门函数就可以