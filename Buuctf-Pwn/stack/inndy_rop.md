这个题目是一个32位静态链接的程序

学到了使用ROPgadget直接生成rop链

```bash
ROPgadget --binary rop --ropchain
```

直接会返回一个python2的脚本，可以直接跑出shell

只需要修改一下填充的偏移就可以