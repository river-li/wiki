USENIX2020的文章，Shattered Chain of Trust: Understanding Security Risks in Cross-Cloud IoT Access Delegation



## TLDR



## Abstract

IoT云会在IoT设备和用户之前起到访问控制的作用，用户可以远程通过IoT云访问自己的设备。但是由于IoT设备厂商各不相同，有些用户不喜欢下载许多的APP，一些厂商就会把设备接入到Google、IFTTT这样的平台中，例如飞利浦Hue和SmartTings云都支持将设备访问权限委托（delegate）到Google Home这样的云平台上，这样用户就可以通过Google Home访问自己各种不同厂商的设备。

这样一个场景下产生的问题就是，各个厂商之间的access delegation protocol并不统一，其中传输的数据可能会导致未授权访问的问题。

这篇文章对这样一个问题提出了系统的研究，提出了一种半自动化的工具对这一类的问题进行形式化验证，并发现了一些漏洞。




## Introduction

这里提出的一个场景是，Philips Hue可以接入Google Home的云，一个Airbnb的房东可能会短暂的将相关设备的控制权交给这里的租客，这种能力的交接就涉及到cross-cloud delegation，由于一些厂商的相关标准不统一，导致这一过程中就会出现一些问题；

