import subprocess

cli_cmd = './build/bin/vsentry_cli'

def run_cmd(cmd):
	cmd_list = cmd.split();
	reply = subprocess.check_output(cmd_list)
	return reply.split()

def create_group(group_type, group_name, values):
	delete_cmd = cli_cmd + ' delete group ' + group_type + ' ' + group_name
	update_cmd = cli_cmd + ' update group ' + group_type + ' ' + group_name + ' ' + values
	show_cmd = cli_cmd + ' show group ' + group_type + ' ' + group_name
	try:
		run_cmd(delete_cmd)
	except subprocess.CalledProcessError, e:
		print 'Failed delete group: ' + group_name
	run_cmd(update_cmd)
	reply = run_cmd(show_cmd)
	list_values = values.split()
	ind = 4
	print list_values
	for v in list_values:
		if (reply[ind] != v):
			print 'ERROR - Create of ' + group_type + ' failed!!!'
		ind += 1

def create_groups():
	create_group('file-group', 'file_group1', '/work/file1.txt /work/file2.txt')
	create_group('program-group', 'gropram_group1', '/bin/cat /bin/echo')
	create_group('user-group', 'user_group1', 'root arik')
	create_group('mid-group', 'mid_group1', '123 124')
	create_group('can-intf-group', 'caninf_group1', 'vcan0')
	create_group('addr-group', 'addr_group1', '1.2.3.4/24 4.4.4.4/32')
	create_group('addr-group', 'addr_group1', '1.2.3.4/24 4.4.4.4/32')
	create_group('port-group', 'port_group1', '7777 8888')
	create_group('proto-group', 'proto_group1', 'tcp udp')

def is_bm_valid(bm, atype, log, rl, rl_log):
	print 'in valid bm', bm
	return True

def create_action(name, atype, log, rl, rl_log):
	delete_cmd =  cli_cmd + ' delete action ' + name
	update_cmd = cli_cmd + ' update action ' + name + ' action ' + atype + ' log ' + log
	show_cmd = cli_cmd + ' show action ' + name
	print 'lllll', update_cmd
	try:
		run_cmd(delete_cmd)
	except subprocess.CalledProcessError, e:
		print 'Failed delete action: ' + name
	run_cmd(update_cmd)
	reply = run_cmd(show_cmd)
	print 'rrr:', reply
	found = False
	for i in range(0, len(reply)):
		if reply[i] == name:
			print 'found action: ', reply[i]
			if (is_bm_valid(reply[i + 1], atype, log, rl, rl_log) == False):
				print 'ERROR in bm', reply[i]
				break;
			found = True
			break;

def create_actions():
	create_action('action1', 'allow', 'syslog', 'none', 'none')

create_groups()
create_actions()
