# coding:utf8
try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass

# coding:utf8
# 获取所有函数
funcs = currentProgram.getFunctionManager().getFunctions(True)
target_func = 'system'
# 获取名称为system的函数
func = [x for x  in funcs if x.getName() ==  target_func][0]
# 获取对于system函数的交叉引用
refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint())
for item in refs:
    print(item)