#!/usr/bin/python
import socket
from struct import pack, unpack
from random import randrange

from consts import *



# checksum calculation refered from tutorial
# works for even number of items
def checksum(msg):
    # pad 0 to get even
    if (len(msg) % 2 != 0):
        msg += '0'
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = s + w
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff
    return s



# construct IP header
def IP_header(src_ip, dst_ip):
    ip_ihl = 5      # 5 word (1 word 32 bit)
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = randrange(10000, 30000)

    # IP flag: do not fragment
    #ip_flag = 2
    ip_flag = 0

    # fragment offset: 0 for first packet
    # sending entire packets only
    # ip_frag_off = ip_flag << 13
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    
    ip_saddr = socket.inet_aton (src_ip)
    ip_daddr = socket.inet_aton (dst_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
     
    # the ! in the pack format string means network order(=big-endian)
    # for details on all chars in format string:
    # http://docs.python.org/3/library/struct.html
    ip_header = \
            pack(\
            '!BBHHHBBH4s4s' , \
            ip_ihl_ver, \
            ip_tos, \
            ip_tot_len, \
            ip_id, \
            ip_frag_off, \
            ip_ttl, \
            ip_proto, \
            ip_check, \
            ip_saddr, \
            ip_daddr)

    return ip_header


# seq is my seq num to send
# ack_seq is to ack (prev_remote_seq + 1)
# if data presents, (prev_remote_seq + len(data))
# flags is a 6-tuple of 0 and 1s: (URG, ACK, PSH, RST, SYN, FIN)
def TCP_header(src_ip, dst_ip, seq, ack_seq, flags, wnd, data=None):
    tcp_source = SRC_PORT   # source port
    tcp_dest = DST_PORT     # destination port
    tcp_seq = seq
    tcp_ack_seq = ack_seq
    tcp_doff = 5    #4 byte field, size of tcp header, 5 * 4 = 20 bytes

    # set tcp flags
    tcp_urg = flags[0]
    tcp_ack = flags[1]

    # set to 1 when data non empty
    tcp_psh = flags[2]
    tcp_rst = flags[3]
    tcp_syn = flags[4]
    tcp_fin = flags[5]

    # start form cwnd = 1
    # increment when ACKed up to 1000
    tcp_window = socket.htons(wnd)    

    tcp_check = 0
    tcp_urg_ptr = 0

    # the size of TCP header in 32-bit words
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # print ('Building TCP header with flag = ' + str(tcp_flags))
     
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
     
    # pseudo header fields
    source_address = socket.inet_aton(src_ip)
    dest_address = socket.inet_aton(dst_ip)
    temp_checksum = 0
    protocol = socket.IPPROTO_TCP

    if (data != None):
        tcp_length = len(tcp_header) + len(data)
    else:
        tcp_length = len(tcp_header)

    psh = pack('!4s4sBBH' , source_address , dest_address , temp_checksum, protocol , tcp_length);
    if (data == None):
        psh = psh + tcp_header
    else:
        psh = psh + tcp_header + data 
    tcp_check = checksum(psh)
     
    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack(\
            '!HHLLBBH' , \
            tcp_source, \
            tcp_dest, \
            tcp_seq, \
            tcp_ack_seq, \
            tcp_offset_res, \
            tcp_flags,  \
            tcp_window) + \
            pack('H' , tcp_check) + \
            pack('!H' , tcp_urg_ptr)
    return tcp_header


