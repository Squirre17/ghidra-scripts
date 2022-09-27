#TODO write a description for this script
#@author 
#@category execise
#@keybinding 
#@menupath Tools.Misc.Pipe Decoder
#@toolbar 


#TODO Add User Code Here
funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
for func in funcs:
  func.getBasicBlocks()
