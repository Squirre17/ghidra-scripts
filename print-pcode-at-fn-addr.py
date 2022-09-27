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

def get_hfunc(fn):
  # high function representation
  decomp = DecompInterface()
  decomp.openProgram(currentProgram)
  timout = 60
  dRes = decomp.decompileFunction(fn, timout, getMonitor())
  hfunc = dRes.getHighFunction()
  return hfunc

tgt_fn_addr = 0x12394
fnMngr = currentProgram.getFunctionManager()
addr = toAddr(tgt_fn_addr)
fn = fnMngr.getFunctionAt(addr)
# print("{}".format(fn))
hfn = get_hfunc(fn)
pcodes = hfn.getPcodeOps()

for p in pcodes:
  print("pcode is {}".format(p))



