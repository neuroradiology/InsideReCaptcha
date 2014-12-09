#!/usr/bin/python2
#-*- encoding: Utf-8 -*-
from struct import unpack, pack
from re import search, sub

"""
Recaptcha disassembler - 0.1
By the ReCaptchaReverser
I release this to public domain.
"""

strings = [None] * 256
nums = [None] * 256
strfunc = []
strkey = None
nbSet = 0

def NOP():
    print 'nop'

def NOP_POP():
    pop()
    print 'nop'

def MOV_PTR2PTR():
    src, dst = pop(), pop()
    if ltype(dst) in (-1, -2):
        print 'mov [%d], STRING [%d]' % (dst, src)
    elif ltype(src) == 1:
        print 'mov [%d], BYTE [%d]' % (dst, src)
    elif ltype(src) == 2:
        print 'mov [%d], WORD [%d]' % (dst, src)
    elif ltype(src) == 4:
        print 'mov [%d], DWORD [%d]' % (dst, src)
    else:
        print 'mov [%d], [%d]' % (dst, src)

def MOV_IMM2PTR():
    dst = pop()
    op = ltype(dst)
    if op > 0:
        val = 0
        for i in xrange(op):
            val <<= 8
            val |= pop()
        print 'mov [%d], %d' % (dst, val)
        if dst == 1:
            setKey(val)
        nums[dst] = val
    elif op != -3:
        length = pop() << 8 | pop()
        if op == -1:
            if strkey:
                string = ''.join(strkey[pop() << 8 | pop()] for i in xrange(length))
            else:
                string = ''.join(chr(pop()) for i in xrange(length))
        else:
            string = ''.join(chr(pop()) for i in xrange(length))
        strings[dst] = string
        print 'mov [%d], %s' % (dst, repr(string))
    else:
        exit('err')

def MOV_ARR2PTR():
    srcArr, srcInd, dst = pop(), pop(), pop()
    print 'mov [%d], [%d][%d]' % (dst, srcArr, srcInd)
    
    if strings[srcInd] == 'toString':
        strfunc.append(dst)
    
    if strings[srcInd]:
        if srcArr == 10 and strings[srcInd] != 'M':
            strings[dst] = 'M.prototype.' + strings[srcInd]
        else:
            strings[dst] = strings[srcInd]
    elif strings[srcArr] and nums[srcInd] is not None:
        strings[dst] = (strings[srcArr], nums[srcInd], opcodes[nums[srcInd]])
    
    global key3
    if dst == 1:
        if nbSet == 0:
            key3 = sub('([\\s{};()]|[-+]{2}|default)+', '', key3).replace('\\\\', '\\') + "T;`\n~Rz#_@)}(' {$"
            hashKey(key3)
        elif nbSet == 1:
            hashKey('QBcwSQ' + 'string' + 'function' + 'string')
        elif nbSet == 2:
            hashKey('slAq1sb0' + 'www.google.com')
        elif nbSet == 3:
            key3 = sub('([\\s{};()]|[-+]{2}|default)+', '', key3).replace('\\\\', '\\') + 'bO_WpoE'
            hashKey(key3)
        else:
            exit('Unimplemented key...')

def MOV_TYP2PTR():
    src, dst = pop(), pop()
    print 'mov [%d], TYPEOF[%d]' % (dst, src)

def CONCAT():
    src, dst = pop(), pop()
    if ltype(src) == -1 and ltype(dst) == -1:
        print 'mov [%d], STRING [%d]+[%d]' % (dst, dst, src)
    elif ltype(dst) == -2:
        if ltype(src) < 0:
            print 'mov [%d], ARRAY [%d]+LEN[%d]+[%d]' % (dst, dst, src, src)
        else:
            print 'mov [%d], ARRAY [%d]+%d' % (dst, dst, ltype(src))
    else:
        exit('err')

def EVAL():
    src, dst = pop(), pop()
    print 'mov [%d], EVAL[%d]' % (dst, src)
    
    if strings[src]:
        strings[dst] = strings[src]

def SUB():
    src, dst = pop(), pop()
    print 'sub [%d], [%d]' % (dst, src)

def CALL():
    func, dst, args, self = pop(), pop(), pop() - 1, pop()
    args = '], ['.join(map(str, (pop() for i in xrange(args))))
    print 'mov [%d], [%d]([%s], self=[%d])' % (dst, func, args, self)
    
    global key3
    global strkey
    if func in strfunc and strings[self]:
        if type(strings[self]) == tuple:
            #print '---> psh ' + strings[self][0] + '[' + str(strings[self][1]) + '] ' + getArr(strings[self][0], strings[self][1])
            newOpcodes.append(opcodes[strings[self][1]])
            key3 += getArr(strings[self][0], strings[self][1])
        else:
            #print '---> psh ' + strings[self] + ' ' + getFunc(strings[self])
            key3 += getFunc(strings[self])
    elif dst == 5:
        print 'Enabling string substitution...'
        strkey = key3
        key3 = ''

def MOD():
    src, dst = pop(), pop()
    print 'mod [%d], [%d]' % (dst, src)

def LISTEN():
    elem, event, cb, arg0 = pop(), pop(), pop(), pop()
    print 'listen elem=[%d], event=[%d], callback=[%d], arg0=[%d]' % (elem, event, cb, arg0)

def MOV_PTR2ARR():
    dstArr, dstInd, src = pop(), pop(), pop()
    print 'mov [%d][%d], [%d]' % (dstArr, dstInd, src)
    
    global opcodes
    if strings[dstInd] == 'M':
        print 'Setting new opcodes...'
        opcodes = newOpcodes
    elif strings[dstArr] == 'M':
        print 'Switching opcode...'
        opcodes[nums[dstInd]] = strings[src][2]

def ADD():
    src, dst = pop(), pop()
    if ltype(dst) == -2:
        if ltype(src) == -1:
            print 'add [%d], STRING [%d]' % (dst, src)
        else:
            print 'add [%d], ARRAY [%d]' % (dst, src)
    else:
        print 'add [%d], [%d]' % (dst, src)

def MOV_NOTZERO():
    dst, src = pop(), pop()
    print 'mov_nz [%d], [%d]' % (dst, src)

def INC_IFEQ():
    cmp1, cmp2, dst = pop(), pop(), pop()
    print 'inc_ifeq [%d] == [%d] ? [%d]++' % (cmp1, cmp2, dst)

def INC_IFGT():
    cmp1, cmp2, dst = pop(), pop(), pop()
    print 'inc_ifgt [%d] > [%d] ? [%d]++' % (cmp1, cmp2, dst)

def SHR():
    src, shift, dst = pop(), pop(), pop()
    print 'mov [%d], [%d] << %d' % (dst, src, shift)

def OR():
    or1, or2, dst = pop(), pop(), pop()
    print 'mov [%d], [%d] | [%d]' % (dst, or1, or2)

def PUSHL():
    src = pop()
    print 'pushl [%d]' % src

def POPL():
    nbpos = pop()
    if nbpos:
        pos = '], ['.join(map(str, (pop() for i in xrange(nbpos))))
        print 'popl [%s]' % pos
    else:
        print 'popl'

def INC_IFIN():
    needle, haystack, dst = pop(), pop(), pop()
    print 'inc_ifin [%d] in [%d] ? [%d]++' % (needle, haystack, dst)

def MOV_CLB2PTR():
    dst, cb, arg0 = pop(), pop(), pop()
    print 'mov [%d], callback=[%d], arg0=[%d]' % (pop(), pop(), pop())

def MUL():
    src, dst = pop(), pop()
    print 'mul [%d], [%d]' % (dst, src)

def SHL():
    src, shift, dst = pop(), pop(), pop()
    print 'mov [%d], [%d] >> %d' % (dst, src, shift)

def JSOR():
    or1, or2, dst = pop(), pop(), pop()
    print 'mov [%d], [%d] || %d' % (dst, or1, or2)

def CALL2():
    func, dst, args, self = pop(), pop(), pop() - 1, pop()
    args = '], ['.join(map(str, (pop() for i in xrange(args))))
    print 'mov [%d], [%d][%d]([%s])' % (dst, self, func, args)

def CALL3():
    obj, func, chunklen, arg2 = pop(), pop(), pop(), pop()
    print 'call [%d], [%d]{[%d]}, [%d]' % (func, obj, chunklen, arg2)

opcodes = [
NOP,
MOV_PTR2PTR,
MOV_IMM2PTR,
NOP_POP,
MOV_ARR2PTR,
MOV_TYP2PTR,
CONCAT,
EVAL,
SUB,
CALL,
MOD,
LISTEN,
MOV_PTR2ARR,
NOP,
ADD,
MOV_NOTZERO,
INC_IFEQ,
INC_IFGT,
SHR,
OR,
PUSHL,
POPL,
INC_IFIN,
MOV_CLB2PTR,
MUL,
SHL,
JSOR,
CALL2,
CALL3
]

newOpcodes = []

def ltype(num):
    if num <= 17:
        if num in (2, 4, 14, 15):
            return -2
        elif num in (6, 9, 10, 16):
            return -3
        elif num == 5:
            return -1
        elif num in (7, 12, 0, 3, 8):
            return 2
        elif num == 11:
            return 1
        else:
            return 4
    else:
        return (1, 2, 4, -2, -3, -1)[num % 6]

def getFunc(func):
    func = search('[^a-zA-Z]%s=(function.+)' % func, model).group(1)
    level = 0
    for i in xrange(len(func)):
        if func[i] == '{':
            level += 1
        elif func[i] == '}':
            level -= 1
            if not level:
                func = func[:i+1]
                break
    return func

def getArr(arr, index):
    arr = search('[^a-zA-Z]%s=(\[.+)' % arr, model).group(1)
    level = 0
    lastIndex = 1
    elems = []
    for i in xrange(len(arr)):
        if arr[i] == ',' and level == 1:
            elems.append(arr[lastIndex:i])
            lastIndex = i + 1
        elif arr[i] in '{[(':
            level += 1
        elif arr[i] in '}])':
            level -= 1
            if not level:
                elems.append(arr[lastIndex:i])
                break
    return elems[index]

key3 = ''

def t32(num):
    return unpack('>i', pack('>I', num & 0xFFFFFFFF))[0]

def hashKey(stri):
    print 'Trying to decrypt...'
    state = [0x9e3779b9, 0x9e3779b9, 0x12b9b0a1]
    for i in xrange(0, len(stri), 12):
        block = unpack('>3i', stri[i:i+12].ljust(12,'\0'))
        for j in xrange(3):
            state[j] += block[j]
        factors = [13, 8, 13, 12, 16, 5, 3, 10, 15]
        for j in xrange(len(factors)):
            d = state[((j % 3) + 2) % 3]
            state[j % 3] = t32((state[j % 3] - state[((j % 3) + 1) % 3] - d) ^ (t32(d << factors[j]) if j % 3 == 1 else ((d & 0xFFFFFFFF) >> factors[j])))
    setKey(state[2] & 0xffffffff)
    
    global nbSet
    nbSet += 1

def setKey(key_):
    print 'Key set to', key_, 'at pos', fd.tell()
    global key
    global seed
    key = key_
    seed = unpack('>I', fd.read(4))[0]

def teaEnc(word1, word2, key):
    acc = 0
    word1 &= 0xffffffff
    word2 &= 0xffffffff
    for i in xrange(32):
        word1 += ((word2 << 4 ^ word2 >> 5) + word2) ^ (acc + key[acc & 3])
        word1 &= 0xffffffff
        acc += 0x9e3779b9
        word2 += ((word1 << 4 ^ word1 >> 5) + word1) ^ (acc + key[acc >> 11 & 3])
        word2 &= 0xffffffff
    return [word1 >> 24 & 255, word1 >> 16 & 255, word1 >> 8 & 255, word1 & 255,
            word2 >> 24 & 255, word2 >> 16 & 255, word2 >> 8 & 255, word2 & 255]

def pop():
    pos = fd.tell()
    byte = fd.read(1)
    if not byte:
        print 'EOF! :)'
        exit(0)
    ctext = teaEnc(seed, pos / 8, [0, 0, 0, key])
    return ord(byte) ^ ctext[pos % 8]

with open('model.js') as fd:
    model = fd.read()

with open('enc') as fd:
    setKey(0)
    while True:
        opcodes[pop() % 29]()
