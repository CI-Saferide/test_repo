import json
import collections
import sys, getopt

def write_file_rule(rule, rule_id, action, file_name , perm, user, exec_prog):
  rule['systemPolicies'].insert(0, collections.OrderedDict())
  rule['systemPolicies'][0]['priority'] = rule_id
  rule['systemPolicies'][0]['id'] = 11
  rule['systemPolicies'][0]['fileName'] = file_name
  rule['systemPolicies'][0]['permissions'] = perm
  rule['systemPolicies'][0]['execProgram'] = exec_prog
  rule['systemPolicies'][0]['user'] = user
  rule['systemPolicies'][0]['actionName'] = action

def main(argv):
  rule_type = ''
  is_delete = False
  try:
     opts, args = getopt.getopt(argv,"ht:n:f:u:p:a:d")
  except getopt.GetoptError:
     print 'ceate_test_rule.py -t <rule_type>'
     sys.exit(2)
  for opt, arg in opts:
     if opt == '-h':
        print 'ceate_test_rule.py -t <rule_type>'
        sys.exit()
     elif opt in ("-t"):
        rule_type = arg
     elif opt in ("-n"):
        rule_id = arg
     elif opt in ("-a"):
        action = arg
     elif opt in ("-f"):
        file_name = arg
     elif opt in ("-p"):
        perm = arg
     elif opt in ("-d"):
        is_delete = True

  rule = collections.OrderedDict()
  rule['canVersion'] = 238
  rule['ipVersion'] = 238
  rule['systemVersion'] = 238
  rule['actionVersion'] = 238
  rule['actions'] = []
  rule['actions'].insert(0, {})
  rule['actions'][0]['id'] = 1111
  rule['actions'][0]['name'] = 'allow'
  rule['actions'][0]['drop'] = False
  rule['actions'][0]['allow'] = True
  rule['actions'][0]['log'] = False
  rule['actions'].insert(1, {})
  rule['actions'][1]['id'] = 1112
  rule['actions'][1]['name'] = 'allow_log'
  rule['actions'][1]['drop'] = False
  rule['actions'][1]['allow'] = True
  rule['actions'][1]['log'] = True
  rule['actions'].insert(2, {})
  rule['actions'][2]['id'] = 1113
  rule['actions'][2]['name'] = 'drop'
  rule['actions'][2]['drop'] = True
  rule['actions'][2]['allow'] = False
  rule['actions'][2]['log'] = True
  rule['systemPolicies'] = []
  rule['canPolicies'] = []
  rule['ipPolicies'] = []
  if is_delete:
      return
  if (rule_type == 'file'):
      write_file_rule(rule, rule_id, action, file_name , perm, '*',  '*')

  print json.dumps(rule)

if __name__ == "__main__":
   main(sys.argv[1:])
