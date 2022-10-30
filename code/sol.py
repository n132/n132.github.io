from z3 import *
X   = [ [ Int("x_%s_%s" % (i, j)) for j in range(14) ] for i in range(14) ]
rules = [ And(0 <= X[i][j], X[i][j] <= 1) for i in range(14) for j in range(14) ] + [(sum([X[i][_] for _ in range(14)])==3) for i in range(14)] + [(sum([X[_][i] for _ in range(14)])==3) for i in range(14)] + [ sum(X[xx[0]][xx[1]] for xx in [ (i,j) for i in range(14) for j in range(14) if [ [ 1 if (ord(xx)==x+ord('a')) else 0 for xx in 'aaaaabbbbcccddaaaaabbbbccccdaaeaaabbbccccdaaefaabbbcccgdeeefffffbccggdfeeffffggggggdfffffffhhhgggdffffhhhhhhgggdffijjjjhkkllmdiiijjkkkkkllmmiijjjkkkklllmmiijjjkkkklllmmijjjjjkknnllmmijjjjnnnnnllll'] for x in range(14) ][x][i*14+j]==1 ])==3 for x in range(14)]+ [ If( X[i][j]==1, sum([ X[i+k][j+l] if (i+k>=0 and j+l>=0 and i+k<14 and j+l<14) else 0 for k in [-1,0,1] for l in [-1,0,1]])==1, True) for i in range(14) for j in range(14)]
s = Solver()
s.add(rules)
print("".join([str([ [ s.model().evaluate(X[i][j]) for j in range(14) ] for i in range(14) ][x][y]) for x in range(14) for y in range(14)])) if s.check() == sat else print("failed to solve")



# ins = [ [ 1 if (ord(xx)==x+ord('a')) else 0 for xx in pz] for x in range(14) ] 
# r0  = [ And(0 <= X[i][j], X[i][j] <= 1) for i in range(14) for j in range(14) ]
# r1  = [(sum([X[i][_] for _ in range(14)])==3) for i in range(14)]
# r2  = [(sum([X[_][i] for _ in range(14)])==3) for i in range(14)]
# r3  = [ sum(X[xx[0]][xx[1]] for xx in [ (i,j) for i in range(14) for j in range(14) if ins[x][i*14+j]==1 ])==3 for x in range(14)]
# r4  = [ If( X[i][j]==1, sum([ X[i+k][j+l] if (i+k>=0 and j+l>=0 and i+k<14 and j+l<14) else 0 for k in [-1,0,1] for l in [-1,0,1]])==1, True) for i in range(14) for j in range(14)]
