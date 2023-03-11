import re
import os


f = open("TTPs.txt", "r")
f2 = open("1.txt", "w")
linez = f.readlines()
for i in range(0,len(linez),3):
    line1 = linez[i]
    line2 = linez[i+1]
    l = line1 + line2
    l = ''.join(l.splitlines())
    f2.write(l)
    f2.write("\n")
f.close()
f2.close()

f = open("final.txt", "w")
f2 = open("1.txt", "r")

linez2 = f2.readlines()
for line in linez2:
    la = line.split("\t")
    for el in la:
        if el[:1] == ".":
            la.remove(el)
        if el == "Enterprise":
            la.remove(el)
    f.writelines("\t".join(la))

f.close()
f2.close()

f3 = open("1.txt", "w")
f = open("final.txt", "r")
linez = f.readlines()
for i in range(len(linez)-1):
    sl = linez[i]
    sl = re.sub(r"\[.+\]", "", sl)
    if linez[i+1][:1] != "T":
        sl = sl.rstrip()
        sl = sl + "\t"
    f3.write(sl)

f.close()
f3.close()


f = open("1.txt", "r")
f3 = open("TTPs.txt", "w")
linez = f.readlines()
for line in linez:
    la = line.split("\t")
    ml = la[0] + "\t" + la[1] + "\t" + la[2]
    if len(la) > 3:
        ml = ml + "\n"
        f3.write(ml)
        for m in range(3, len(la), 2):
            ml = la[m] + "\t" + la[m+1]
            if(m != len(la) - 2):
                f3.write(ml+"\n")
            else:
                f3.write(ml)
    else:
        f3.write(ml)

f.close()
f3.close()

os.remove("1.txt")
os.remove("final.txt")






