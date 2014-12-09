#!/usr/bin/python2
#-*- encoding: Utf-8 -*-
from struct import unpack, pack
from re import search, sub, match
from copy import copy

"""
Recaptcha decompiler - 0.1
By the ReCaptchaReverser
I release this to public domain.
"""

strings = [None] * 256
nums = [None] * 256
ptr = []
ptrWithArg = []
labels = []
strfunc = []
strkey = None
nbSet = 0
tab = ''

def NOP():
    print tab + '// nop'

def NOP_POP():
    pop()
    print tab + '// nop'

def MOV_PTR2PTR():
    src, dst = pop(), pop()
    
    imm = type(heap[src][0]) == int
    
    if ltype(dst) in (-1, -2):
        if type(heap[src]) == list and len(heap[src]) == 1 and type(heap[src][0]) in (str, unicode):
            heap[dst] = [heap[src]]
        else:
            heap[dst] = [heap[src], '']
    elif ltype(src) == 1 and not (imm and heap[src][0] <= 0xff):
        heap[dst] = [heap[src], Oper('&', 0xff)]
    elif ltype(src) == 2 and not (imm and heap[src][0] <= 0xffff):
        heap[dst] = [heap[src], Oper('&', 0xffff)]
    elif ltype(src) == 4 and not (imm and heap[src][0] <= 0xffffffff):
        heap[dst] = [heap[src], Oper('&', 0xffffffff)]
    else:
        heap[dst] = [heap[src]]
    
    if dst == 1:
        print tab + '_setKey(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst == 0:
        print tab + 'goto %s;' % get(heap[dst])
        if get(heap[dst]).isdigit() and int(get(heap[dst])) not in labels:
            labels.append(int(get(heap[dst])))
        heap[dst] = [Var(dst)]
    elif dst == 13:
        print tab + '_setXhr2Key(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst <= 17:
        print tab + 'v%d = %s;' % (dst, get(heap[dst]))
        heap[dst] = [Var(dst)]

def MOV_IMM2PTR():
    dst = pop()
    op = ltype(dst)
    if op > 0:
        val = 0
        for i in xrange(op):
            val <<= 8
            val |= pop()
        if dst == 1:
            setKey(val)
        nums[dst] = val
    elif op != -3:
        length = pop() << 8 | pop()
        if op == -1:
            if strkey:
                val = ''.join(strkey[pop() << 8 | pop()] for i in xrange(length))
            else:
                val = ''.join(chr(pop()) for i in xrange(length)).decode('utf8')
        else:
            val = ''.join(chr(pop()) for i in xrange(length))
        strings[dst] = val
    else:
        exit('err')
    heap[dst] = [val]
    
    if dst == 8:
        print tab + '_setEndFunction(f%d);' % val
        if val < fd.tell():
            exit('pointer to back: unhandled')
        ptr.append(val)
    elif dst == 1:
        print tab + '_setKey(%d);' % val
    elif dst == 0:
        print tab + 'goto %d;' % val
        if val not in labels:
            labels.append(val)
    elif dst == 13:
        print tab + '_setXhr2Key(%d);' % val
    elif dst <= 17:
        print tab + 'v%d = %s;' % (dst, get(heap[dst]))

def MOV_ARR2PTR():
    srcArr, srcInd, dst = pop(), pop(), pop()
    heap[dst] = [Obj(heap[srcInd], heap[srcArr])]
    
    if dst == 1:
        print tab + '_setKey(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst == 0:
        print tab + 'goto %s;' % get(heap[dst])
        if get(heap[dst]).isdigit() and int(get(heap[dst])) not in labels:
            labels.append(int(get(heap[dst])))
        heap[dst] = [Var(dst)]
    elif dst == 13:
        print tab + '_setXhr2Key(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst <= 17:
        print tab + 'v%d = %s;' % (dst, get(heap[dst]))
        heap[dst] = [Var(dst)]
    
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
    print tab + 'v%d = _getType(%s);' % (dst, get(heap[src]))
    heap[dst] = [Var(dst)]

def CONCAT():
    src, dst = pop(), pop()
    if ltype(src) == -1 and ltype(dst) == -1:
        heap[dst].append(heap[src])
    elif ltype(dst) == -2:
        if ltype(src) < 0:
            if ltype(src) == -1:
                print tab + '_concat(%s, _intToWord(_utf8encode(%s).length));' % (get(heap[dst]), get(heap[src]))
                print tab + '_concat(%s, _utf8encode(%s));' % (get(heap[dst]), get(heap[src]))
            else:
                print tab + '_concat(%s, _intToWord(%s.length));' % (get(heap[dst]), get(heap[src]))
                print tab + '_concat(%s, %s);' % (get(heap[dst]), get(heap[src]))
        else:
            print tab + '_concat(%s, _intToBytes(%s));' % (get(heap[dst]), get(heap[src]))
        if not isinstance(heap[dst][0], Global):
            heap[dst] = [Var(dst)]
    else:
        exit('err')

def EVAL():
    src, dst = pop(), pop()
    if type(heap[src]) == list and len(heap[src]) == 1 and type(heap[src][0]) in (str, unicode):
        if (match('^[a-zA-Z_$][a-zA-Z_$0-9]*$', heap[src][0]) or match('^/[^/]+/[a-z]*$', heap[src][0])) and dst > 17:
            heap[dst] = [Global(heap[src][0])]
        elif match('^[0-9]*\.[0-9]+$', heap[src][0]) and dst > 17:
            heap[dst] = [float(heap[src][0])]
        else:
            print tab + 'v%d = %s;' % (dst, heap[src][0])
            heap[dst] = [Var(dst)]
    elif type(heap[src]) == list and len(heap[src]) == 2 and get(heap[src][0]) == "'0,'" and type(heap[src][1]) == list and len(heap[src][1]) == 1 and isinstance(heap[src][1][0], Obj) and heap[src][1][0].val == 'toString()':
        heap[dst] = [heap[src][1][0].parent]
    else:
        print tab + 'v%d = eval(%s);' % (dst, get(heap[src]))
        heap[dst] = [Var(dst)]
    
    if strings[src]:
        strings[dst] = strings[src]

def SUB():
    src, dst = pop(), pop()
    if len(heap[src]) == 1 and type(heap[src][0]) in (int, float):
        for i in xrange(len(heap[dst])):
            if isinstance(heap[dst][i], Oper) and heap[dst][i].type_ == '-' and type(heap[dst][i].val) in (int, float):
                heap[dst][i].val += heap[src][0]
                return
    heap[dst].append(Oper('-', copy(heap[src])))

def CALL():
    func, dst, args, self = pop(), pop(), pop() - 1, pop()
    
    if type(heap[func]) == list and len(heap[func]) == 1:
        heap[func] = heap[func][0] # ???
    
    if type(heap[func].val) == list and len(heap[func].val) == 1 and heap[func].val[0] == 'toString' and not args:
        heap[dst] = [Obj('toString()', heap[self])]
    else:
        args = ', '.join(get(heap[pop()]) for i in xrange(args))
        print tab + 'v%d = %s(%s);' % (dst, get(Obj(heap[func].val, heap[self])), args)
        heap[dst] = [Var(dst)]
    
    if dst == 1:
        print tab + '_setKey(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst == 0:
        print tab + 'goto %s;' % get(heap[dst])
        if get(heap[dst]).isdigit() and int(get(heap[dst])) not in labels:
            labels.append(int(get(heap[dst])))
        heap[dst] = [Var(dst)]
    elif dst == 13:
        print tab + '_setXhr2Key(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst <= 17:
        print tab + 'v%d = %s;' % (dst, get(heap[dst]))
        heap[dst] = [Var(dst)]
    
    global key3
    global strkey
    if func in strfunc and strings[self]:
        if type(strings[self]) == tuple:
            newOpcodes.append(opcodes[strings[self][1]])
            key3 += getArr(strings[self][0], strings[self][1])
        else:
            key3 += getFunc(strings[self])
    elif dst == 5:
        strkey = key3
        key3 = ''

def MOD():
    src, dst = pop(), pop()
    if len(heap[dst]) > 1:
        heap[dst] = [Parenthese(heap[dst]), Oper('%', copy(heap[src]))]
    else:
        heap[dst].append(Oper('%', copy(heap[src])))

def LISTEN():
    elem, event, cb, arg0 = pop(), pop(), pop(), pop()
    cb = get(heap[cb])
    print tab + '%s.addEventListener(%s, _createCallback(%s, %s), false);' % (get(heap[elem]), get(heap[event]), cb, get(heap[arg0]))
    if int(cb) < fd.tell():
        exit('pointer to back: unhandled')
    ptr.append(int(cb))
    ptrWithArg.append(int(cb))

def MOV_PTR2ARR():
    dstArr, dstInd, src = pop(), pop(), pop()
    print tab + '%s = %s;' % (get(Obj(heap[dstInd], heap[dstArr])), get(heap[src]))
    
    global opcodes
    if strings[dstInd] == 'M':
        opcodes = newOpcodes
    elif strings[dstArr] == 'M':
        opcodes[nums[dstInd]] = strings[src][2]

def ADD():
    src, dst = pop(), pop()
    if ltype(dst) == -2:
        if ltype(src) == -1:
            print tab + '_concat(%s, _utf8encode(%s));' % (get(heap[dst]), get(heap[src]))
        else:
            print tab + '_concat(%s, %s);' % (get(heap[dst]), get(heap[src]))
    else:
        if len(heap[src]) == 1 and type(heap[src][0]) in (int, float):
            for i in xrange(len(heap[dst])):
                if type(heap[dst][i]) in (int, float):
                    heap[dst][i] += heap[src][0]
                    return
            heap[dst].append(heap[src][0])
        else:
            heap[dst].append(copy(heap[src]))

def MOV_NOTZERO():
    cmp1, src = pop(), pop()
    print tab + 'if(v%d != 0) {\n%s    goto %s;\n%s}' % (cmp1, tab, get(heap[src]), tab)
    if get(heap[src]).isdigit() and int(get(heap[src])) not in labels:
        labels.append(int(get(heap[src])))
    heap[0] = [Var(0)]

def INC_IFEQ():
    cmp1, cmp2, dst = pop(), pop(), pop()
    heap[dst].append(Oper('+', Parenthese([cmp1, Oper('==', cmp2), Oper('?', 1), Oper(':', 0)])))

def INC_IFGT():
    cmp1, cmp2, dst = pop(), pop(), pop()
    heap[dst].append(Oper('+', Parenthese([cmp1, Oper('>', cmp2), Oper('?', 1), Oper(':', 0)])))

def SHL():
    src, shift, dst = pop(), pop(), pop()
    heap[dst] = [heap[src], Oper('<<', shift)]

def OR():
    or1, or2, dst = pop(), pop(), pop()
    heap[dst] = [heap[or1], Oper('|', copy(heap[or2]))]

def PUSHL():
    src = pop()
    print tab + 'f%d();' % get(heap[src])

def POPL():
    global tab
    nbpos = pop()
    if tab != '':
        if nbpos:
            pos = '], ['.join(map(str, (pop() for i in xrange(nbpos))))
            print tab + 'return %s;' % get(heap[pos])
        else:
            print tab + 'return;'
        tab = ''
        print '}'

def INC_IFIN():
    needle, haystack, dst = pop(), pop(), pop()
    heap[dst].append(Oper('+', Parenthese([needle, Oper('in', haystack), Oper('?', 1), Oper(':', 0)])))

def MOV_CLB2PTR():
    dst, cb, arg0 = pop(), pop(), pop()
    print tab + 'v%d = _setCallback(%s, %s);' % (dst, get(heap[cb]), get(heap[arg0]))
    if int(heap[cb]) < fd.tell():
        exit('pointer to back: unhandled')
    ptr.append(int(heap[cb]))
    ptrWithArg.append(int(heap[cb]))
    heap[dst] = [Var(dst)]

def MUL():
    src, dst = pop(), pop()
    if len(heap[dst]) == 1:
        heap[dst].append(Oper('*', copy(heap[src])))
    else:
        heap[dst] = [Parenthese(heap[dst]), Oper('*', copy(heap[src]))]

def SHR():
    src, shift, dst = pop(), pop(), pop()
    heap[dst] = [heap[src], Oper('>>', shift)]

def JSOR():
    or1, or2, dst = pop(), pop(), pop()
    heap[dst] = [heap[or1], Oper('||', heap[or2])]

def CALL2():
    func, dst, args, self = pop(), pop(), pop() - 1, pop()
    args = ', '.join(map(str, (pop() for i in xrange(args))))
    print tab + 'v%d = new %s(%s);' % (dst, get(Obj(heap[func], heap[self])), args)
    heap[dst] = [Var(dst)]
    
    if dst == 1:
        print tab + '_setKey(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst == 0:
        print tab + 'goto %s;' % get(heap[dst])
        if get(heap[dst]).isdigit() and int(get(heap[dst])) not in labels:
            labels.append(int(get(heap[dst])))
        heap[dst] = [Var(dst)]
    elif dst == 13:
        print tab + '_setXhr2Key(%s);' % get(heap[dst])
        heap[dst] = [Var(dst)]
    elif dst <= 17:
        print tab + 'v%d = %s;' % (dst, get(heap[dst]))
        heap[dst] = [Var(dst)]

def CALL3():
    obj, func, chunklen, arg2 = pop(), pop(), pop(), pop()
    print tab + 'for(i = 0; i < %s.length; i += %s) {\n%s    %s(%s.slice(i, i + %s), %s);\n%s}' % (get(heap[obj]), get(heap[chunklen]), tab, get(heap[func]), get(heap[obj]), get(heap[chunklen]), get(heap[arg2]), tab)

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
SHL,
OR,
PUSHL,
POPL,
INC_IFIN,
MOV_CLB2PTR,
MUL,
SHR,
JSOR,
CALL2,
CALL3
]

newOpcodes = []

class Oper:
    type_ = None # string of operator
    val = None # int
    
    def __init__(self, type_, val):
        self.type_ = type_
        self.val = val

class Obj:
    val = None # str / int / Var / list
    parent = None # Obj / None
    
    def __init__(self, val, parent=None):
        self.val = val
        self.parent = parent

class Var:
    num = None # int
    
    def __init__(self, num):
        self.num = num

class Parenthese:
    val = None # int
    
    def __init__(self, val):
        self.val = val

class Global:
    name = None # str
    
    def __init__(self, name):
        self.name = name

def get(obj, asparent=False, hasstr=False):
    if not isinstance(obj, Obj):
        obj = Obj(obj)
    
    while isinstance(obj.val, Obj) or (type(obj.val) == list and len(obj.val) == 1):
        if type(obj.val) == list and len(obj.val) == 1:
            obj.val = obj.val[0]
        
        if isinstance(obj.val, Obj):
            obj = obj.val
    
    if type(obj.val) in (str, unicode) and obj.parent:
        if obj.val == 'toString()' and hasstr:
            return get(obj.parent, asparent, hasstr)
        nobj = obj.val
    elif isinstance(obj.val, Global):
        nobj = obj.val.name
    elif type(obj.val) in (str, unicode):
        nobj = repr(obj.val).lstrip('u')
    elif type(obj.val) == int and obj.val & 0xff == 0xff:
        nobj = hex(obj.val)
    elif type(obj.val) in (int, float):
        nobj = str(obj.val)
    elif isinstance(obj.val, Var):
        nobj = 'v' + str(obj.val.num)
    elif isinstance(obj.val, Parenthese):
        nobj = '(' + get(obj.val.val) + ')'
    elif type(obj.val) == list:
        ihasstr = False # Mecanism to avoid useless .toString() in concatenations
        nobj = get(obj.val[0])
        if nobj[0] in '\'"' or nobj.endswith('.toString()'):
            ihasstr = True
        for i in obj.val[1:]:
            if isinstance(i, Oper):
                nobj += ' ' + i.type_ + ' ' + get(i.val)
            else:
                toadd = get(i, hasstr=ihasstr)
                if toadd[0] in '\'"' or toadd.endswith('.toString()'):
                    ihasstr = True
                nobj += ' + ' + toadd
    else:
        exit('bad type: ' + str(type(obj.val)))
    
    if obj.parent and type(obj.val) in (str, unicode):
        parent = get(obj.parent, True)
        if parent == 'window':
            return nobj
        else:
            return parent + '.' + nobj
    elif obj.parent:
        return get(obj.parent, True) + '[' + nobj + ']'
    else:
        if asparent and type(obj.val) == list:
            nobj = '(' + nobj + ')'
        return nobj

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
heap = [[Var(i)] for i in xrange(256)]
heap[4] = [Global('xhr1')]
heap[9] = [Global('window')]
heap[10] = [Global('this')]
heap[14] = [Global('xhr2')]
heap[16] = [Global('arg0')]

def t32(num):
    return unpack('>i', pack('>I', num & 0xFFFFFFFF))[0]

def hashKey(stri):
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
    global tab
    pos = fd.tell()
    if pos in ptr:
        if pos in ptrWithArg:
            print tab + 'function f%d(arg0) {' % pos
        else:
            print tab + 'function f%d() {' % pos
        tab = '    '
    if pos in labels:
        print 'label %d:' % pos
    byte = fd.read(1)
    if not byte:
        print tab + '// EOF! :)'
        exit(0)
    ctext = teaEnc(seed, pos / 8, [0, 0, 0, key])
    return ord(byte) ^ ctext[pos % 8]

with open('model.js') as fd:
    model = fd.read()

with open('enc') as fd:
    setKey(0)
    while True:
        opcodes[pop() % 29]()
