#!/usr/bin/python

# Coding tutorials referenced:
# www.binarytides.com/raw-socket-programming-in-python-linux/
# www.binarytides.com/python-packet-sniffer-code-linux/


# DST IP: 216.97.236.245
# http://david.choffnes.com/classes/cs4700sp16/2MB.log
# http://david.choffnes.com/classes/cs4700sp16/10MB.log
# http://david.choffnes.com/classes/cs4700sp16/project4.php


# DST IP: 129.10.116.81
# http://www.ccs.neu.edu 

# local and remote ports
SRC_PORT = 29110
DST_PORT = 80

# local buffer size is 4096
MAX_LEN = 4096
MAX_RETRY = 30

# if a sent packet is not ACKed within 60 sec
# assume loss and retransmit
MAX_WAIT = 60

# if no data is received within 360 sec
# assume connection failure and exit
MAX_TIME = 360
MAX_CWND = 1000
RAND_SEED = 4294967295

# init window sizes: 1 MSS as unit
INIT_CWND = 1
INIT_AWND = 1

# interval between retransmit (sec)
INTERVAL = 0.1

# external shell scripts for iptable rules
SETUP_IPTABLE = './set_iptable'
RESTORE_IPTABLE = './restore_iptable'

# wait for RST to take effect on ending previous session
INIT_WAIT = 10


