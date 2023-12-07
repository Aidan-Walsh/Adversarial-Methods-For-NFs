import sys
# remove all comments in a rules file and write to new rules file
file = sys.argv[1]

f = open(file,"r")

f2 = open("update.rules", "w")

for i in f:
  
  if i[0] != "#":
    f2.write(i)
  else:
    f2.write(i[1:])