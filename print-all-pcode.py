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

fns = currentProgram.getFunctionManager().getFunctions(True)
tgt_fn_name = "main"
tgt_fn = [x for x in fns if x.getName() == tgt_fn_name][0]


def get_hfunc(fn):
  # high function representation
  decomp = DecompInterface()
  decomp.openProgram(currentProgram)
  timout = 60
  dRes = decomp.decompileFunction(fn, timout, getMonitor())
  hfunc = dRes.getHighFunction()
  return hfunc

h_tgt_fn = get_hfunc(tgt_fn)
# getPcodeOps will return AST
pcodes = h_tgt_fn.getPcodeOps()# get all pcodes in this fn

# bacause PcodeOp inherits from PcodeOp so getOpcode method is avaiable
for p in pcodes:
  if p.getOpcode() == PcodeOp.PTRSUB:
    print("pcode is {}".format(p))
    # print("pcodePoASTs getInput(0) is {}".format(p.getInput(0)))
