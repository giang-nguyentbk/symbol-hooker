# symbol-hooker
```bash
$ export LD_LIBRARY_PATH=./bin:D_LIBRARY_PATH
$ make clean
$ make
# Open two terminals
# Terminal 1
$ make target
# Press enter, you will see function and global variable work correctly
# Redo "make target" and go to terminal 2


# Terminal 2
$ make got
# If Operation not permitted, run
$ sudo su
$ make got
```

## Normal case
![](./assets/normal.png?raw=true)


## GOT Hooked
![](./assets/got_hooked.png?raw=true)