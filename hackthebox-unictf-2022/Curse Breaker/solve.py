import os
import re
os.system("(python -c 'print(\"a\")' | seccomp-tools dump ~/ctf/htb/rev_cursebreaker/breaker) > dump")
f = open("dump")
dump = f.read()
flag = ""
lines = (dump.split("\n"))
chars = [0,0]
for i in lines[5:]:
    s = re.search("\((.*)\)",i)
    try: n = (s.group(1)[5:])
    except: n = None
    if n!=None:
        if n[1] != "x":
            char = int(n)
            if (char & 0x80000000): char -= 0x100000000
            chars.append(char)
            flag += chr(chars[-1]+chars[-2])
        else:
            chars = [0,0]
f.close()
print(flag)
