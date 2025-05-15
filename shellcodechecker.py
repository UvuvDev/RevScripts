from pwn import *
import sys

"""
This script has you input shellcode and it'll check if any bytes are unusable: so if you're
putting shellcode into something with scanf for example, it will detect what instruction will
have a space character so you can change it. 
"""

context.arch = 'amd64'

inputShellcode = ""
readShellcode = ""

illegalBytes = int(input("Enter illegal bytes as hex numbers (format 0011223344) - "), base=16)
illegalBytesCnt = int(input("and also how many you inputted (for the above example, 5) - "))

def compileAndCheckForBytes(line):

    shellcode = asm(readShellcode)

    byteCheck = illegalBytes
    for i in range(0, illegalBytesCnt):
        for j in shellcode:
            if j == (byteCheck & 0xFF): # If an illegal byte is seen, return True
                print(asm(line), end="")
                return i
        byteCheck = byteCheck >> 8    
        
    return -1

# Open the shellcode and read the full assembly file
with open(sys.argv[1], 'r') as file:
    inputShellcode = file.read()

# Start checking line by line to identify illegal instructions
lineNum = 0
with open(sys.argv[1], "r") as file:
    while True:
        line = file.readline()
        lineNum += 1
        readShellcode = readShellcode + line
        
        if not line:
            break  # Stop when end of file is reached

        check = compileAndCheckForBytes(line)

        if check != -1:
            print(" - instruction in hex. On line " + str(lineNum) + ", this instruction - " + line.strip() +
            " - had an illegal byte: " +
            ' '.join(f'0x{(illegalBytes >> (8 * check)) & 0xFF:02x}' for i in range(1)))
            exit()

        print("Ok L" + str(lineNum))
    

print("All Clear!")
