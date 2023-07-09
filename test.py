'''
Author: squirre17 3319277663@qq.com
Date: 2022-09-17 12:16:16
LastEditors: squirre17 3319277663@qq.com
LastEditTime: 2022-10-26 16:33:31
FilePath: \ghidra_scripts\test.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
#TODO write a description for this script
#@author 
#@category execise
#@keybinding 
#@menupath Tools.Misc.Pipe Decoder
#@toolbar 


#TODO Add User Code Here
def get_hfunction(fn):
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 60
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    return hfunction

funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
for func in funcs:
    func.getBasicBlocks()
