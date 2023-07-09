
#@author 
#@category execise
#@keybinding 
#@menupath Tools.Misc.Pipe Decoder
#@toolbar 
# coding:utf8

try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

# coding:utf8
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp, Varnode
from ghidra.program.model.symbol import RefType
from ghidra.program.model.listing import FunctionIterator
from ghidra.program.model.symbol import ReferenceIterator

def get_hfunction(func):
    """
    get high representation of this func
    """
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 60
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    return hfunction

def get_vn_val(vn):
    '''
    vn: Varnode
    '''
    if vn.isConstant():
        return vn.getOffset()
    vn_def = vn.getDef()  # get it's SSA defination
    if not vn_def:
        return None
    if vn_def.getOpcode() == PcodeOp.COPY:
        return get_vn_val(vn_def.getInput(0))

# get all functions
#  funcs : FunctionIterator 
funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
# get function named "system"
funcs = [x for x in funcs if x.getName() ==  target_func]

# get all xrefs for system func 
# refs : list[ReferenceIterator]
refs = []

for func in funcs:
    refs += currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())

for item in refs:
    calling_func = getFunctionContaining(item.getFromAddress())  # get the function where xref is located
    if not calling_func:
        continue
    high_calling_func = get_hfunction(calling_func)              # get high representation about this function 
    xrefs_pcodes = high_calling_func.getPcodeOps(item.getFromAddress()) # get pcodes where xref is located
    call_pcodes = [x for x  in xrefs_pcodes if x.getOpcode() == PcodeOp.CALL]
    if not call_pcodes:  # find corresponding pcode for CALL op 
        continue

    call_pcode = call_pcodes[0]
    first_param_vn = call_pcode.getInput(1) # get corresponding varnode for 1st argu
    vn_val = get_vn_val(first_param_vn)  # get corresponding value for above vn
    if vn_val:
        data = getDataAt(toAddr(vn_val)) # get the value for specific address
        print('system @{} {}'.format(item.getFromAddress(),data.getValue()))