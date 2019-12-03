# SROP

> View the article about srop at [here](https://www.jianshu.com/p/8e147f5eb05d)

## SROP learn exercise

### pwnable.kr-unexploitable
- directly use SROP to create fake frame and exec SYS_execve with /bin/sh .

### 360ichunqiu 2017-smallest
- use SROP fake syscall to mprotect the stack executable and then exec our shellcode.
- either directly use SROP to exec SYS_execve with /bin/sh directly.

both two methods are included in the `exp.py`