#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here
# coding:utf8
try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

# coding:utf8
# get all functions
# getFunctionManager => Returns the program's datatype manager.
funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
# get function named system
# for i in funcs:
#   print(i.getName())
func = [ x for x  in funcs if x.getName() ==  target_func][0]
print(func)
print(func.getEntryPoint())
# get xref fpr system
refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
for item in refs:
  print(item)
