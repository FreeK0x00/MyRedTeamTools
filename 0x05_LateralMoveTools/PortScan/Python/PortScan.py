#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# version: "1.0"
# author: "FreeK0x00"

import socket
import sys
import threading
import argparse
import time
import platform
import subprocess


class Logger(object):
	def __init__(self, filename='result.txt', stream=sys.stdout):
		self.terminal = stream
		self.log = open(filename, 'a')

	def write(self, message):
		self.terminal.write(message)
		self.log.write(message)

	def flush(self):
		pass


def ping_func(ip):
	if platform.system() == 'Windows':
		ping = subprocess.Popen(
            'ping -n 1 {}'.format(ip),
            shell=False,
            close_fds=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
	else:
		ping = subprocess.Popen(
			'ping -c 1 {}'.format(ip),
			shell=False,
			close_fds=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE
		)
	try:
		out, err = ping.communicate(timeout=8)
		if 'ttl' in out.decode('GBK').lower():
			print("[+] {} is alive".format(ip))
	except:
		pass
	ping.kill()


def IPScan(ip):
    network = ip
    print('[*] Current scan network: ' + network)
    if '/24' in ip:
        ipc = (ip.split('.')[:-1])
        for i in range(1, 256):
            ip = ('.'.join(ipc)+'.'+str(i))
            threading._start_new_thread(ping_func, (ip,))
            time.sleep(0.1)
    elif '/16' in ip:
        ipc = (ip.split('.')[:-2])
        for i in range(1, 256):
            iplist = ['.'.join(ipc) + '.'+str(i) + '.' + '1', '.'.join(ipc) + '.'+str(i) + '.' + '2', '.'.join(ipc) + '.'+str(i) + '.' + '253', '.'.join(ipc) + '.'+str(i) + '.' + '254']
            for ipp in iplist:
                threading._start_new_thread(ping_func, (ipp,))
                time.sleep(0.1)
    else:
        ping_func(ip)
    print('[*] IP alive scan on %s complete' % network)


def PortConnect(ip, p):
	""" Creates a TCP socket and attempts to connect via supplied ports """
	sql_port = [3306, 1521, 1433, 5432, 27017]
	port = int(p)
	try:
		# Create a new socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if port in sql_port:
			s.settimeout(5)
		else:
			s.settimeout(0.2)
		# Print if the port is open
		if not s.connect_ex((ip, port)):
			print('[+] %s:%d/TCP Open' % (ip, port))
	except Exception:
		pass
	finally:
		s.close()


def GetPorts(ip, ports):
	print('[*] Starting TCP port scan on IP %s' % ip)
	for p in ports:
		PortConnect(ip, p)
	print('[*] TCP port scan on IP %s complete' % ip)
	print('[*] ------------------------------------------------------------')


def CscanPort(ip, ports):
	network = ip
	print('[*] Current TCP port scan network: ' + network)
	ipc = (ip.split('.')[:-1])
	for i in range(1, 256):
		ip = ('.'.join(ipc)+'.'+str(i))
		threading._start_new_thread(GetPorts, (ip, ports))
		time.sleep(0.1)
	print('*] TCP port scan on %s complete' % network)

Usage = """
Args desc:
	-i , --ip, IP or IP/24 or IP/24 or IP/8
	-p , --port, Scan Port list, Eg: 80 80-89 80,443,3306,8080
	-f , --ipfile, Test IP list file, Eg: ip.txt
	-o , --output, Output scan results to a file
	-a , --alive, help="Scan IP list if alive
	-h , --help, help info
Usage eg:
python3 PortScan.py -i 192.168.0.1              # Default Ports Scan
python3 PortScan.py -i 192.168.0.1 -p 8080,8081,4444
python3 PortScan.py -i 192.168.0.1 -p 8080-8085
python3 PortScan.py -i 192.168.0.1 -p 8080,8081,4441-4445
python3 PortScan.py -i 192.168.0.1 -p 8080,8081,4441-4445 -o ./test.txt
python3 PortScan.py -i 192.168.0.1 -a true
python3 PortScan.py -i 192.168.0.1/24 -a true
python3 PortScan.py -i 192.168.0.1/16 -a true
python3 PortScan.py -f ip.txt -o ./test.txt     # Default Ports Scan
python3 PortScan.py -p 80,81,8081  -f ip.txt -o ./test.txt
python3 PortScan.py -i 192.168.0.1/24 -p 8080,8081,4441-4445
"""

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--ip', help='IP or IP/24 or IP/24 or IP/8')
	parser.add_argument('-p', '--port', help="Scan Port list, Eg: 80 80-89 80,443,3306,8080")
	parser.add_argument('-f', '--ipfile', help="Test IP list file, Eg: ip.txt")
	parser.add_argument('-o', '--output', help="Output scan results to a file")
	parser.add_argument('-a', '--alive',  type=bool, help="Scan IP list if alive")
	args = parser.parse_args()
	ip = args.ip
	tmpPorts = args.port
	ipfile = args.ipfile
	outfile = args.output
	argalive = args.alive
	if ip is None and ipfile is None:
		print('[-] Error: ip or ipfile is Null!')
		print(Usage)
		sys.exit(1)

	if outfile:
		sys.stdout = Logger(filename=outfile, stream=sys.stdout)
	else:
		sys.stdout = Logger(stream=sys.stdout)

	if argalive:
		IPScan(ip)
		sys.exit(1)

	if tmpPorts:
		if ',' in tmpPorts and '-' not in tmpPorts:
			ports = tmpPorts.split(',')
			print(ports)
		elif '-' in tmpPorts and ',' not in tmpPorts:
			ports = tmpPorts.split('-')
			tmpports = []
			[tmpports.append(i) for i in range(int(ports[0]), int(ports[1]) + 1)]
			ports = tmpports
			print(ports)
		elif '-' in tmpPorts and ',' in tmpPorts:
			ports = tmpPorts.split(',')
			for p in ports:
				if '-' in str(p):
					ports.remove(p)
					tmp = p.split('-')
					[ports.append(str(i)) for i in range(int(tmp[0]), int(tmp[1]) + 1)]
			print(ports)
		else:
			print('[-] Error: portlist is illegal!! Please check and try again!!')
			print(Usage)
			sys.exit(1)
	else:
		print('Start Scan {} Default Ports'.format(ip))
		ports = [21, 22, 53, 80, 81, 82, 88, 135, 443, 445, 1433, 1521, 3306, 3389, 4444, 5432, 5900, 6379, 7001, 8000, 8080, 8081, 8082, 8083, 8090, 8444, 8888, 27017]
		print('[*] Default Ports list: ', ports)

	if ip:
		if '/24' in ip:
			CscanPort(ip, ports)
		else:
			GetPorts(ip, ports)
	elif ipfile:
		iplist = []
		with open(str(ipfile)) as f:
			while True:
				line = str(f.readline()).strip()
				if line:
					iplist.append(line)
				else:
					break
		print('[*] Get IP list: ', iplist)
		for ip in iplist:
			GetPorts(ip, ports)