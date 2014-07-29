#
#   Simple CDB(console windbg) crashdetector
#
#       chpie@grayhash
#       License : BSD
#
#
#   Dependency
#       windbg
#       MSEC exploitable
#

import os
import re
import sys
import time
import threading
import subprocess

################################ config

timeout_seconds = 60

sympath = "SRV*c:\\code\\symbols*http://msdl.microsoft.com/download/symbols;SRV*c:\\code\\symbols*http://chromium-browser-symsrv.commondatastorage.googleapis.com;"
CDB_PATH = 'cdb.exe -y "%s" -G -o -cfr script.txt' % sympath

#################################

timer = None
crash_report_cmd = '!exploitable;.lastevent;r;u .;k;qd'
events = ['asrt', 'av', 'dm', 'dz', 'c000008e', 'gp', 'ii', 'iov', 'ip', 'isc', 'lsq', 'sbo', 'sov', 'chhc', 'ssessec', 'bpebpec', '80000003']

hoho = []
for ev in events:
    hoho.append('sx- -c "%s" %s\n' % (crash_report_cmd, ev))

script = \
'''
.logopen "%s\\cdb_log.txt"
.load msec
%s
sxi ibp
sxn wos
sxn wob
sx- -c "q" 3c
.pcmd -s "gn"
g
''' % (os.getcwd(), ''.join(hoho))

def kill_cdb(popo):
    global timer
    try: popo.terminate()
    except: pass
    try: timer.cancel()
    except: pass

def test(cmd):
    global timeout_seconds
    global timer

    f = open('script.txt', 'wb+')
    f.write(script)
    f.close()

    #
    # Create new process group for COOL display
    #
    p = subprocess.Popen(args=cmd, 
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NEW_CONSOLE)

    timer = threading.Timer(timeout_seconds, kill_cdb, [p])
    timer.start()
    p.wait()
    try: timer.cancel()
    except: pass

def sx( regular_expression, data ):
    ret = re.search(regular_expression, data)
    if None != ret: ret = ret.group(1)
    return ret.strip()

def zzz(unik):
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()[]'
    ret = ''
    for ch in unik:
        if ch not in charset: ch = '_'
        ret += ch
    while '__' in ret: ret = ret.replace('__', '_')

    return ret


def parser(data):
    if 'Exploitability Classification:' not in data: return False

    data = data[ data.find('Exploitability Classification') : ]

    ev_class = sx("Exploitability Classification: (.+)[\r\n]*", data)
    ev_title = sx("Recommended Bug Title: (.+)[\r\n]*", data)
    ev_event = sx("Last event: [a-f0-9A-F]+\.[a-f0-9A-F]+: (.+) - code", data)
    instruction = sx("[\r\n]+[a-f0-9A-F]+[ \t]+[a-f0-9A-F]+[ \t]+(.+)[\r\n]+", data)
    at = sx("[\r\n]+(.+)[\r\n]+[a-f0-9A-F]+[ \t]+[a-f0-9A-F]+[ \t]+.+[\r\n]+", data)

    if ev_class and ev_title and ev_event and instruction:
        while '  ' in instruction: 
            instruction = instruction.replace('  ', ' ')

        print '[METAINFO_BEGIN]'
        print data
        print '[METAINFO_END]'
        print 'CLASS = ', ev_class
        print 'TITLE = ', ev_title
        print 'EVENT = ', ev_event
        print 'INSTRUCTION = ', instruction
        print 'AT = ', at

        return True

    return False

def wait_for_process_die(die):
    while True:
        p = subprocess.Popen('tasklist', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        so, se = p.communicate()
        if die not in so: break
        time.sleep(1)

##############################################################

if len(sys.argv) != 3:
    ##
    #
    #   0 : self
    #   1 : target application
    #   2 : url
    #
    print 'Invalid arguments %s != 3' % len(sys.argv)
    quit()

cmd = sys.argv[1]
arguments = sys.argv[2]

die = cmd[ cmd.rfind('\\') + 1 : cmd.rfind('.exe') + 4 ]

test(CDB_PATH + ' ' + cmd + ' ' + arguments)
wait_for_process_die(die)
if parser(open('cdb_log.txt', 'rb').read()) == True:
    os.system('tskill werfault')









