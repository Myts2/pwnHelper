'''
Usage:pwnHelper.py <binary>
Use Ctrl-C to finish record and name the function
If you input a var, you can input the data with defined var name
eg: 111#index
it can create a function var named `index`

And you can find solve.*.py in current folder

Don't use Ctrl-C to close the program, just close the terminal window. #TODO

Have Fun!
'''


import select
from pwn import *
from sys import argv,stdin
import time

context.log_level = "debug"

curLine = ""
instructList = []
varList = []
io = process(argv[1])
solveFile = "solve"+time.time().hex()[3:-3]+".py"

epoll = select.epoll()
epoll.register(io.fileno(), select.EPOLLIN)
epoll.register(stdin.fileno(), select.EPOLLIN)

with open(solveFile, "w+") as f:
    f.write("from pwn import *\n")
    f.write("io = process('%s')\n\n\n" % argv[1])

def sigint_handler(signum, frame):
    funcName = raw_input("func_name: ")
    initInstruct(funcName[:-1], varList)
    showInstruct()
    record()

signal.signal(signal.SIGINT, sigint_handler)
# signal.signal(signal.SIGHUP, sigint_handler)
# signal.signal(signal.SIGTERM, sigint_handler)

def initInstruct(funcName,argvs,n=4):
    global instructList
    tmpList = []
    tmpList.append("def %s(%s):" % (funcName,",".join(argvs)))
    instructList = tmpList+instructList
    # ins = "io.recvuntil(%s)" % io.recvline()
    # instructList.append(" "*n+ins)

def addInstruct(input,status,n=4):
    if status == "recv":
        ins = r"io.recvuntil('%s')" % input
        instructList.append(" " * n + ins)
        return input
    if status == "send":
        rawInput = input.split("#")
        print rawInput
        if len(rawInput) == 1:
            ins = r"io.sendline('%s')" % rawInput[0]
        else:
            ins = r"io.sendline(%s)" % (rawInput[1])
            varList.append(rawInput[1])

        instructList.append(" " * n + ins)
        return rawInput[0]


def showInstruct():
    global instructList,varList,curLine
    finalIns = "\n".join(instructList)
    print finalIns
    with open(solveFile,"a+") as f:
        f.write(finalIns+"\n"*2)
    instructList = []
    varList = []



def readProcess():
    rawRecv = io.recv(1024)
    recvList = rawRecv.split("\n")
    if recvList[-1] == "":
        return recvList[-2]
    return recvList[-1]

def record():
    global curLine
    while(1):
        events = epoll.poll(1)
        for fileno, event in events:
            if fileno == stdin.fileno():
                # recv = readProcess()
                # print recv
                addInstruct(curLine,"recv")
                input = stdin.readline()
                sendOut = addInstruct(input[:-1],"send")
                io.sendline(sendOut)
                curLine = readProcess()

curLine = readProcess()
record()