import sys, getopt
import os

def main(argv):
   open_type = ''
   file_name = ''
   try:
      opts, args = getopt.getopt(argv,"o:f:")
   except getopt.GetoptError:
      print 'open_file.py -f <filename> -o <r|w>'
      sys.exit(2)
   for opt, arg in opts:
      if opt in ("-o"):
         open_type = arg
      elif opt in ("-f"):
         file_name = arg

   with open(file_name, open_type) as f:
     print ''

if __name__ == "__main__":
   main(sys.argv[1:])
