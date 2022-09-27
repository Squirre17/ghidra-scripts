# coding:utf8
try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

# coding:utf8
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType
def get_hfunction(func):
    """
    获取某个函数的高级表示
    """
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 60
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    return hfunction

def get_vn_val(vn):
    if vn.isConstant():
        return vn.getOffset()
    vn_def = vn.getDef()  #获取其SSA定义
    if not vn_def:
        return None
    if vn_def.getOpcode() == PcodeOp.COPY:
        return get_vn_val(vn_def.getInput(0))

# 获取所有函数
funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
# 获取名称为system的函数
funcs = [x for x  in funcs if x.getName() ==  target_func]

# 获取对于system函数的交叉引用
refs = []
for func in funcs:
    refs += currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
for item in refs:
    calling_func = getFunctionContaining(item.getFromAddress())  # 获取交叉引用所在函数
    if not calling_func:
        continue
    high_calling_func = get_hfunction(calling_func)  # 获取函数的高级表示
    xrefs_pcodes = high_calling_func.getPcodeOps(item.getFromAddress()) # 获取交叉引用处的pcodes
    call_pcodes = [x for x  in xrefs_pcodes if x.getOpcode() == PcodeOp.CALL]
    if not call_pcodes:  # 找到CALL对应的pcode
        continue
    call_pcode = call_pcodes[0]
    first_param_vn = call_pcode.getInput(1) # 获取第一个参数对应的varnode
    vn_val = get_vn_val(first_param_vn)  # 获取varnode对应的值
    if vn_val:
        data = getDataAt(toAddr(vn_val)) # 获取特定地址的值
        print('system @{} {}'.format(item.getFromAddress(),data.getValue()))