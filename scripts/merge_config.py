import sys
import getopt

def usage():
  print 'usage: ', sys.argv[0], ' -o old_file -n new_file'
  sys.exit(2)

try:
  opts, args = getopt.getopt(sys.argv[1:], 'o:n:')
except getopt.GetoptError as err:
  usage()

for o, a in opts:
  if o == '-n':
    new_file = a
  if o == '-o':
    old_file = a

if (not 'new_file' in vars()) or (not 'old_file' in vars()):
  usage()

old_d = {}
with open(old_file) as f:
  for line in f:
    if not line[0].isalpha():
      continue
    (key, val) = line.split()
    old_d[key] = val

with open(new_file) as f:
  for line in f:
    if not line[0].isalpha():
      print line,
      continue
    (key, val) = line.split()
    if key in old_d.keys():
      print key, old_d[key]
    else:
      print line,
