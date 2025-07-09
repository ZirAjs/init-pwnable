from pwn import *
import clipboard

context.log_level = "error"
context.arch = "amd64"

WORKDIR = "./problem"
EXECUTABLE = f"{WORKDIR}/prob"

HOST = "localhost"
PORT = 7138


elf = ELF(EXECUTABLE)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def connect():
    if PORT is None:
        return process(EXECUTABLE)
    else:
        return remote(HOST, PORT)


def payload():
    payload: bytes = b"A" * 0x100
    clipboard.copy(payload.decode("latin-1"))
    return payload


if __name__ == "__main__":
    p = connect()
    p.recvuntil(b": ")
    p.sendline(payload())
    p.interactive()
    p.close()
