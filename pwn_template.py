from pwn import *
import clipboard

context.log_level = "error"
context.arch = "amd64"

WORKDIR = "./problem"
EXECUTABLE = f"{WORKDIR}/problem/prob"

HOST = "localhost"
PORT = 7138


# e = ELF(EXECUTABLE)
# libc_e = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def connect():
    if PORT is None:
        return process(EXECUTABLE)
    else:
        return remote(HOST, PORT)


p = connect()
p.interactive()
p.close()
