#TODO write a description for this script
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
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType
def get_hfunction(func):
    """
    get high representation
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
    vn_def = vn.getDef()  # get SSA definition (return a PcodeOp)
    if not vn_def:
        return None
    if vn_def.getOpcode() == PcodeOp.COPY:
        return get_vn_val(vn_def.getInput(0))

# get all functions
funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
# get funtcion named system
funcs = [x for x  in funcs if x.getName() == target_func]
# there find 2 external system

# get xref for system
refs = []
for func in funcs:
    refs += currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())

for item in refs:
    calling_func = getFunctionContaining(item.getFromAddress())  # get function which xref locate
    if not calling_func:
        continue
    high_calling_func = get_hfunction(calling_func)  # get high representation for function
    xrefs_pcodes = high_calling_func.getPcodeOps(item.getFromAddress()) # get pcodes for xref's location

    call_pcodes = [ x for x in xrefs_pcodes if x.getOpcode() == PcodeOp.CALL ]
    if not call_pcodes:  # find pcode corresponding to CALL
        continue
    call_pcode = call_pcodes[0]
    # i think may more for loop
    first_param_vn = call_pcode.getInput(1) # get varnode corresponding to the first argument

    vn_val = get_vn_val(first_param_vn)  # get value corresponding to varnode 
    if vn_val:
        data = getDataAt(toAddr(vn_val)) # get value of specific address
        print('system @ {} {}'.format(item.getFromAddress(),data.getValue()))

# vernode and pcode all printable 