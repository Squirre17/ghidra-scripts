a = [1, 2, 3]
f = [x for x in a if x != 1][0]
print(f)
f = [x for x in a if x != 1]
print(f)