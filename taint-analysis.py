# coding:utf8
#@category execise
try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

try:
    import queue as Queue
except:
    import Queue

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import HighFunctionDBUtil
def get_hfunction(func):
    # get high function
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 60
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    return hfunction

def DBG(x):
  print("[DEBUG] " + x)

def find_vuln_in_func(seed):
    varnodes = set()
    worklist = Queue.Queue()
    worklist.put(seed)
    while not worklist.empty():
        curvn = worklist.get()
        if curvn in varnodes:
            continue
        else:
            varnodes.add(curvn)
        # iter 获取所有把curvn作为input的 pcode list
        iter = curvn.getDescendants()# iterator to all PcodeOps that take this as input
        while iter.hasNext():
            op = iter.next()
            if not op:
                continue
            if op.getOpcode() == PcodeOp.CALL:
                called_func = getFunctionAt(op.getInput(0).getAddress())
                #TODO: 这两个b一样？？？ CALL的input[0]就是要调用的函数
                # DBG("op is {}".format(op))
                # DBG("op.getInput(0).getAddress() is {}".format(op.getInput(0).getAddress()))
                # DBG("called_func is {}".format(called_func.getEntryPoint()))
                if called_func.getName() == 'popen':
                    # DBG("seed vn is {}".format(seed))
                    print("Found vuln {} @ {} -> {} @ {}"
                      .format(
                        source_func_name,
                        seed.getDef().getSeqnum().getTarget(),
                        sink_func_name,
                        op.getSeqnum().getTarget()
                      )
                    )
                if called_func.getName() == 'sprintf':
                    curvn = op.getInput(1) # input[0] is function addr, input[1] is register
                    curvn_def = curvn.getDef() # get the pcode op this varnode belongs to
                    # DBG("curvn_def is {}".format(curvn_def))
                    if curvn_def.getOpcode() == PcodeOp.PTRSUB: # 局部变量 因为栈上都是RSP + off寻址
                        # DBG("curvn_def is {}".format(curvn_def))
                        vn_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, curvn_def)
                        # DBG("vn_addr is {}".format(vn_addr))
                        for item in seed.getHigh().getHighFunction().getPcodeOps():
                            # DBG("item is {}".format(item))
                            if item.getOpcode() == PcodeOp.PTRSUB:
                                DBG("item curvn_def is {}<->{}".format(item, curvn_def))
                                new_vn_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram,item)
                                DBG("vn_addr new_vn_addr is {}<->{}".format(vn_addr.getOffset(), new_vn_addr.getOffset()))
                                if vn_addr.getOffset() == new_vn_addr.getOffset(): # sprintf的写入变量 和
                                    worklist.put(item.getOutput())
            else:
                curvn = op.getOutput()
            if not curvn:
                continue
            worklist.put(curvn)


source_func_name = 'getenv'
sink_func_name = 'popen'
funcs = currentProgram.getFunctionManager().getFunctions(True)
source_funcs = [x for x  in funcs if x.getName() ==  source_func_name]
refs = []
for func in source_funcs:
    refs += currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
for item in refs:
    calling_func = getFunctionContaining(item.getFromAddress())  # 获取交叉引用所在函数
    if not calling_func:
        continue
    high_calling_func = get_hfunction(calling_func)  # 获取函数的高级表示
    xrefs_pcodes = high_calling_func.getPcodeOps(item.getFromAddress())  # 获取交叉引用处的pcodes
    call_pcodes = [x for x in xrefs_pcodes if x.getOpcode() == PcodeOp.CALL]
    if not call_pcodes:  # 找到CALL对应的pcode
        continue
    call_pcode = call_pcodes[0] # first in all call pcodes
    output_vn = call_pcode.getOutput()  # get output vn corresponding to call pcode (return varnode)
    find_vuln_in_func(output_vn)