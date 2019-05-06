#!/usr/bin/env python2

import subprocess
import argparse
import json

cli_cmd = './build/bin/vsentry_cli'
errs = 0
is_verbose = False

def run_cmd(cmd):
	cmd_list = cmd.split();
	reply = subprocess.check_output(cmd_list)
	return reply.split()

def create_group(group_type, group_name, values):
	global errs
	delete_cmd = cli_cmd + ' delete group ' + group_type + ' ' + group_name
	update_cmd = cli_cmd + ' update group ' + group_type + ' ' + group_name + ' ' + values
	show_cmd = cli_cmd + ' show group ' + group_type + ' ' + group_name
	try:
		run_cmd(delete_cmd)
	except subprocess.CalledProcessError, e:
		if is_verbose:
			print 'Failed delete group: ' + group_name
	try:
		run_cmd(update_cmd)
	except subprocess.CalledProcessError, e:
		print 'Failed update group: ' + group_name
		print 'update cmd:', update_cmd
		errs += 1
		return
	try:
		reply = run_cmd(show_cmd)
	except subprocess.CalledProcessError, e:
		print 'Failed show group: ' + group_name
		print 'show cmd:', show_cmd
		errs += 1
		return
	list_values = values.split()
	if (set(list_values) != set(reply)):
		print 'ERROR - Create of ' + group_type + ' failed!!!'
		errs += 1

def check_groups():
	create_group('file-group', 'file_group1', '/work/file1.txt /work/file2.txt')
	create_group('program-group', 'program_group1', '/bin/cat /bin/echo')
	create_group('user-group', 'user_group1', 'root arik')
	create_group('mid-group', 'mid_group1', '123 124')
	create_group('can-intf-group', 'caninf_group1', 'vcan0')
	create_group('addr-group', 'addr_group1', '1.2.3.4/24 4.4.4.4/32')
	create_group('addr-group', 'addr_group2', '1.2.8.9/24 3.5.5.5/32')
	create_group('port-group', 'port_group1', '7777 8888')
	create_group('port-group', 'port_group2', '6666 9999')
	create_group('proto-group', 'proto_group1', 'tcp udp')

def is_bm_valid(bm, atype, log, rl):
	if (atype == 'none') and (log == 'none') and (rl == 'none') and (bm == '0'):
		return True 
	if (atype == 'drop') and (log != 'none') and (rl == 'none') and (bm == '68'):
		return True
	if (atype == 'allow') and (log != 'none') and (rl == 'none') and (bm == '66'):
		return True
	if (atype == 'allow') and (log == 'none') and (rl == 'none') and (bm == '2'):
		return True
	if (atype == 'allow') and (log != 'none') and (rl == 'drop') and (bm == '74'):
		return True
	return False

def create_action(name, atype, log, rl, rl_log):
	global errs
	delete_cmd =  cli_cmd + ' delete action ' + name
	update_cmd = cli_cmd + ' update action ' + name + ' action ' + atype
	if log != 'none':
		update_cmd += ' log ' + log
	if rl != 'none':
		update_cmd += ' rate_limit_action ' + rl
	if rl_log != 'none':
		update_cmd += ' rate_limit_log ' + rl_log
	show_cmd = cli_cmd + ' show action ' + name
	try:
		run_cmd(delete_cmd)
	except subprocess.CalledProcessError, e:
		if is_verbose:
			print 'Failed delete action: ' + name
	try:
		run_cmd(update_cmd)
	except subprocess.CalledProcessError, e:
		print 'Failed update action: ' + name
		errs += 1
		return
	reply = run_cmd(show_cmd)
	found = False
	for i in range(0, len(reply)):
		if reply[i] == name:
			if is_bm_valid(reply[i + 1], atype, log, rl) == False:
				print 'ERROR in bm', reply[i]
				errs += 1
				break;
			if is_bm_valid(reply[i + 3], rl, rl_log, 'none') == False:
				print 'ERROR in rl bm', reply[i]
				errs += 1
				break;
			if reply[i + 2] != log:
				print 'ERROR in log', reply[i]
				errs += 1
				break;
			if reply[i + 4] != rl_log:
				print 'ERROR in rl log', reply[i]
				errs += 1
				break;
			found = True
			break;

def check_actions():
	create_action('action1', 'allow', 'syslog', 'none', 'none')
	create_action('action1', 'drop', 'syslog', 'none', 'none')
	create_action('action1', 'allow', 'none', 'none', 'none')
	create_action('action1', 'allow', 'file', 'drop', 'syslog')
	create_action('action2', 'allow', 'file', 'drop', 'syslog')

def delete_rule(rule_type, section, rule_number):
	delete_cmd = cli_cmd + ' delete ' + rule_type + ' ' + section + ' rule_number ' + str(rule_number)
	try:
		run_cmd(delete_cmd)
	except subprocess.CalledProcessError, e:
		if is_verbose:
			print 'info: failed delete rule ' + str(rule_number)

def add_rule_field(cmd, is_group, field, value):
	new_cmd = cmd + ' ' + field
	if is_group:
		new_cmd += '_group'
	new_cmd += ' ' + value
	return new_cmd

def get_rule(rule_type, section, rule_number):
	show_cmd = cli_cmd + ' show ' + rule_type + ' ' + section + ' rule_number ' + str(rule_number)
	try:
		reply = run_cmd(show_cmd)
	except subprocess.CalledProcessError, e:
		print 'Failed to get rule : ' + str(rule_number)
		return
	if is_verbose:
		print reply
	i = 0
	while (i < len(reply) and reply[i] != str(rule_number)):
		 i += 1
	if i == len(reply):
		print 'Error getting rule:', str(rule_number)
		return
	return reply[i:]

def is_valid_can_rule(reply, is_mid_group, mid, can_dir, is_if_group, interface, is_program_group, program, is_user_group, user, action):
	rule_mid = reply[1]
	rule_dir = reply[2]
	rule_if = reply[3]
	rule_prog = reply[4]
	rule_user = reply[5]
	rule_action = reply[6]
	if is_mid_group:
		mid  = 'l:' + mid
	if rule_mid.find(mid) == -1:
		print 'mid is not match'
		return False
	if is_if_group:
		interface  = 'l:' + interface
	if rule_if.find(interface) == -1:
		print 'interface is not match'
		return False
	if rule_dir != can_dir:
		print 'dir is not match'
		return False
	if is_program_group:
		program = 'l:' + program
	if rule_prog.find(program) == -1:
		print 'program is not match'
		return False
	if is_user_group:
		user  = 'l:' + user
	if rule_user.find(user) == -1:
		print 'user is not match'
		return False
	if rule_action.find(action) == -1:
		print 'action is not match'
		return False
		
	return True
	
def check_can_rule_add(rule_type, rule_number, is_mid_group, mid, can_dir, is_if_group, interface, is_program_group, program, is_user_group, user, action, is_success, is_delete):
	global errs
	if is_delete:
		delete_rule(rule_type, 'can', rule_number)
	update_cmd = cli_cmd + ' update ' + rule_type + ' can ' + ' rule_number ' + str(rule_number)
	update_cmd = add_rule_field(update_cmd, is_mid_group, 'mid', mid)
	update_cmd += ' dir ' + can_dir
	update_cmd = add_rule_field(update_cmd, is_if_group, 'interface', interface)
	update_cmd = add_rule_field(update_cmd, is_program_group, 'program', program)
	update_cmd = add_rule_field(update_cmd, is_user_group, 'user', user)
	update_cmd += ' action ' + action
	if is_verbose:
		print 'check CAN add rule: ', update_cmd
	try:
		run_cmd(update_cmd)
	except subprocess.CalledProcessError, e:
		if (is_success):
			print 'Failed add can rule : ' + str(rule_number)
			errs += 1
		return
	if not is_success:
		print 'ERROR - invalud rule success, rule:', rule_number
		errs += 1
		return
	reply = get_rule(rule_type, 'can', rule_number)
	if is_verbose:
		print 'reply: ', reply
	if (not is_valid_can_rule(reply, is_mid_group, mid, can_dir, is_if_group, interface, is_program_group, program, is_user_group, user, action)):
		print 'ERROR in CAN rule number:', str(rule_number)
		errs += 1

def is_valid_file_rule(reply, is_file_group, filename, perm, is_program_group, program, is_user_group, user, action):
	rule_file = reply[1]
	rule_perm = reply[2]
	rule_prog = reply[3]
	rule_user = reply[4]
	rule_action = reply[5]
	if is_file_group:
		filename  = 'l:' + filename
	if rule_file.find(filename) == -1:
		print 'ERROR filename is not match'
		errs += 1
		return False
	if rule_perm != perm:
		print 'ERROR perm is not match'
		errs += 1
		return False
	if is_program_group:
		program = 'l:' + program
	if rule_prog.find(program) == -1:
		print 'ERROR program is not match'
		errs += 1
		return False
	if is_user_group:
		user  = 'l:' + user
	if rule_user.find(user) == -1:
		print 'ERROR user is not match'
		errs += 1
		return False
	if rule_action.find(action) == -1:
		print 'ERROR action is not match'
		errs += 1
		return False
	return True

def check_file_rule_add(rule_type, rule_number, is_file_group, filename, perm, is_program_group, program, is_user_group, user, action, is_success, is_delete):
	global errs
	if is_delete:
		delete_rule(rule_type, 'file', rule_number)
	update_cmd = cli_cmd + ' update ' + rule_type + ' file ' + ' rule_number ' + str(rule_number)
	update_cmd = add_rule_field(update_cmd, is_file_group, 'file', filename)
	update_cmd += ' perm ' + perm
	update_cmd = add_rule_field(update_cmd, is_program_group, 'program', program)
	update_cmd = add_rule_field(update_cmd, is_user_group, 'user', user)
	update_cmd += ' action ' + action
	try:
		run_cmd(update_cmd)
	except subprocess.CalledProcessError, e:
		if is_success:
			print 'ERROR Failed add file rule : ' + str(rule_number)
			errs += 1
		return
	if not is_success:
		print 'ERROR success of invalid rule number:', rule_number
		print update_cmd
		errs += 1
		return
	reply = get_rule(rule_type, 'file', rule_number)
	if (not is_valid_file_rule(reply, is_file_group, filename, perm, is_program_group, program, is_user_group, user, action)):
		print 'ERROR in FILE rule number:', str(rule_number)
		errs += 1

def check_can_rules():
	print '---------------- Check CAN Rules'
	with open('can_tests.json') as json_file:  
		tests = json.load(json_file)
	for key, value in tests.iteritems():
		rule_num = value['rule_num']
		is_mid_group = value['is_mid_group']
		mid = value['mid']
		direction = value['dir']
		is_if_group = value['is_if_group']
		inf = value['inf']
		is_program_group = value['is_program_group']
		program = value['program']
		is_user_group = value['is_user_group']
		user = value['user']
		action = value['action']
		is_success = value['is_success']
		is_delete = value['is_delete']
		check_can_rule_add('rule', rule_num, is_mid_group, mid, direction, is_if_group, inf, is_program_group, program, is_user_group, user, action, is_success, is_delete)

def check_file_rules():
	print '---------------- Check FILE Rules'
	with open('file_tests.json') as json_file:  
		tests = json.load(json_file)
	for key, value in tests.iteritems():
		rule_num = value['rule_num']
		is_file_group = value['is_file_group']
		filename = value['file']
		perm = value['perm']
		is_program_group = value['is_program_group']
		program = value['program']
		is_user_group = value['is_user_group']
		user = value['user']
		action = value['action']
		is_success = value['is_success']
		is_delete = value['is_delete']
		check_file_rule_add('rule', rule_num, is_file_group, filename, perm, is_program_group, program, is_user_group, user, action, is_success, is_delete)

def check_ip_rules():
	print '---------------- Check IP Rules'
	with open('ip_tests.json') as json_file:  
		tests = json.load(json_file)
	for key, value in tests.iteritems():
		rule_num = value['rule_num']
		is_src_addr_group = value['is_src_addr_group']
		src_addr = value['src_addr']
		is_dst_addr_group = value['is_dst_addr_group']
		dst_addr = value['dst_addr']
		is_proto_group = value['is_proto_group']
		proto = value['proto']
		is_src_prot_group = value['is_src_prot_group']
		src_port = value['src_port']
		is_dst_prot_group = value['is_dst_prot_group']
		dst_port = value['dst_port']
		is_program_group = value['is_program_group']
		program = value['program']
		is_user_group = value['is_user_group']
		user = value['user']
		action = value['action']
		is_success = value['is_success']
		is_delete = value['is_delete']
		rl = value['rl']
		check_ip_rule_add('rule', rule_num, is_src_addr_group, src_addr, is_dst_addr_group, dst_addr, is_proto_group, proto, is_src_prot_group, src_port, is_dst_prot_group, dst_port, is_program_group, program, is_user_group, user, rl, action, is_success, is_delete)

def is_valid_ip_rule(reply, is_src_addr_group, src_addr, is_dst_addr_group, dst_addr, is_proto_group, proto, is_src_port_group, src_port, is_dst_port_group, dst_port, is_program_group, program, is_user_group, user, action):
	rule_src_addr = reply[1]
	rule_dst_addr = reply[2]
	rule_proto = reply[3]
	rule_src_portr = reply[4]
	rule_dst_portr = reply[5]
	rule_prog = reply[6]
	rule_user = reply[7]
	rule_action = reply[9]
	if is_src_addr_group:
		src_addr  = 'l:' + src_addr
	if rule_src_addr.find(src_addr) == -1:
		print 'ERROR src_addr is not match'
		errs += 1
		return False
	if is_dst_addr_group:
		src_addr  = 'l:' + dst_addr
	if rule_dst_addr.find(dst_addr) == -1:
		print 'ERROR dst_addr is not match'
		errs += 1
		return False
	if is_program_group:
		program = 'l:' + program
	if rule_prog.find(program) == -1:
		print 'ERROR program is not match'
		errs += 1
		return False
	if is_user_group:
		user  = 'l:' + user
	if rule_user.find(user) == -1:
		print 'ERROR user is not match'
		errs += 1
		return False
	if rule_action.find(action) == -1:
		print 'ERROR action is not match'
		errs += 1
		return False
	return True

def check_ip_rule_add(rule_type, rule_number, is_src_addr_group, src_addr, is_dst_addr_group, dst_addr, is_proto_group, proto, is_src_port_group, src_port, is_dst_port_group, dst_port, is_program_group, program, is_user_group, user, rl, action, is_success, is_delete):
	global errs
	if is_delete:
		delete_rule(rule_type, 'ip', rule_number)
	update_cmd = cli_cmd + ' update ' + rule_type + ' ip ' + ' rule_number ' + str(rule_number)
	update_cmd = add_rule_field(update_cmd, is_src_addr_group, 'src_addr', src_addr)
	update_cmd = add_rule_field(update_cmd, is_dst_addr_group, 'dst_addr', dst_addr)
	update_cmd = add_rule_field(update_cmd, is_proto_group, 'proto', proto)
	update_cmd = add_rule_field(update_cmd, is_src_port_group, 'src_port', src_port)
	update_cmd = add_rule_field(update_cmd, is_dst_port_group, 'dst_port', dst_port)
	update_cmd = add_rule_field(update_cmd, is_program_group, 'program', program)
	update_cmd = add_rule_field(update_cmd, is_user_group, 'user', user)
	update_cmd = add_rule_field(update_cmd, False, 'rl', rl)
	update_cmd += ' action ' + action
	try:
		run_cmd(update_cmd)
	except subprocess.CalledProcessError, e:
		if is_success:
			print 'ERROR Failed add ip rule : ' + str(rule_number)
			print update_cmd
			errs += 1
		return
	if not is_success:
		print 'ERROR invalid rule sucees, rule id:' + str(rule_number)
		errs += 1
		return
	reply = get_rule(rule_type, 'ip', rule_number)
	if (not is_valid_ip_rule(reply, is_src_addr_group, src_addr, is_dst_addr_group, dst_addr, is_proto_group, proto, is_src_port_group, src_port, is_dst_port_group, dst_port, is_program_group, program, is_user_group, user, action)):
		print 'ERROR in IP rule number:', str(rule_number)
		errs += 1
	
def check_rules():
	check_can_rules()
	check_file_rules()
	check_ip_rules()

parser = argparse.ArgumentParser()

parser.add_argument("--verbose", help="increase output verbosity",
                    action="store_true")
args = parser.parse_args()
if args.verbose:
	is_verbose = True

print '---------------- Check groups'
check_groups()
print '---------------- Check ations'
check_actions()
print '---------------- Check Rules'
check_rules()

if errs == 0:
	print '\n SUCCESS!'
else:
	print '\n FAILED num of errors:', errs
