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

import Queue
# coding:utf8
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType
from ghidra.program.model.pcode import HighFunctionDBUtil

def get_hfunction(fn):
  # get high function
  decomplib = DecompInterface()
  decomplib.openProgram(currentProgram)
  timeout = 60
  dRes = decomplib.decompileFunction(fn, timeout, getMonitor())
  hfn = dRes.getHighFunction()
  return hfn

# first argu except a varnode
def taint_trace_by_vn(first, inje_fn_name):
  taint_vn_set = set() # no repeat record set
  vnq = Queue.Queue() # varnode queue
  vnq.put(first)
  while not vnq.empty():
    curvn = vnq.get()
    if curvn in taint_vn_set:
      continue
    else:
      taint_vn_set.add(curvn)
    taint_pcodes = curvn.getDescendants() # iterator to all PcodeOps that take this as input
    for t_pcode in taint_pcodes:
      if t_pcode.getOpcode() == PcodeOp.CALL:
        call_fn = getFunctionAt(t_pcode.getInput(0).getAddress())
        if call_fn.getName() == dangerous_fn_name:
          print("Found vuln {} @ {} -> {} @ {}"
            .format(
              inje_fn_name,
              first.getDef().getSeqnum().getTarget(),
              call_fn.getName(),
              t_pcode.getSeqnum().getTarget()
            )
          )
        elif call_fn.getName() == "sprintf":
          t_vn = t_pcode.getInput(1) # sprintf concat string into input[1]
          t_vn_def = t_vn.getDef() # pcode
          if t_vn_def.getOpcode() == PcodeOp.PTRSUB: # from stack
            t_vn_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, t_vn_def)
            for pcode in first.getHigh().getHighFunction().getPcodeOps():
              if pcode.getSeqnum() > t_vn_def.getSeqnum():
                pcode_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, pcode)
                if not pcode_addr:
                  continue
                if pcode_addr.getOffset() == t_vn_addr.getOffset(): # same stack var
                  vnq.put(pcode.getOutput())
        elif call_fn.getName() == "strcpy":
          pass# TODO:
      else:
        t_vn = t_pcode.getOutput()
      if not t_vn:
        continue
      vnq.put(t_vn)
      
# get all functions 
fns = currentProgram.getFunctionManager().getFunctions(True)
taint_fn_name = "getenv"
dangerous_fn_name = "popen"
fn = [f for f in fns if f.getName() == taint_fn_name][0]

refs = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint())
for ref in refs:
    # function that contain ref
    ref_fn = getFunctionContaining(ref.getFromAddress())
    if not ref_fn:
        continue
    h_ref_fn = get_hfunction(ref_fn)
    # getPcodeOps will return a iterator
    ref_pcodes = h_ref_fn.getPcodeOps(ref.getFromAddress())

    call_pcode = [p for p in ref_pcodes if p.getOpcode() == PcodeOp.CALL][0]
    output_vn = call_pcode.getOutput()
    taint_trace_by_vn(output_vn, taint_fn_name)



