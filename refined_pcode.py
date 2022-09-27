#TODO write a description for this script
#@author 
#@category execise
#@keybinding 
#@menupath Tools.Misc.Pipe Decoder
#@toolbar 
import sys,os
try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

# coding:utf8
from ghidra.app.decompiler import DecompInterface


def get_hfunction(func):   # get some function advanced representation
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 60
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    if hfunction is None:
      print("Error hfunction")
      sys.exit(1)
    return hfunction

def print_func_pcode(func):  # print some function's refined pocde
    ret = []
    hfunc = get_hfunction(func)
    for basic_block in hfunc.getBasicBlocks():
        for item in basic_block.getIterator():
            print(item)

print_func_pcode(getFunction('FUN_000114b8'))