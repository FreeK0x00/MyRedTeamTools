import platform
import subprocess
import threading
import argparse
import time

def ping_func(ip):
    if (platform.system() == 'Windows'):
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', help='IP or IP/24 or IP/24 or IP/8')
    parser.add_argument('-a', '--alive', type=bool, help="Scan IP list if alive")
    args = parser.parse_args()
    ip = args.ip
    argalive = args.alive
    if argalive:
        IPScan(ip)
