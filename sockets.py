#!/usr/bin/python
import socket
import time
import sys
from random import randrange

from consts import *
from packets import *
from urlparse import urlparse



# retrieve destination ip from url
def get_dest_ip(url):
    hostname = urlparse(url).netloc
    #print (hostname)
    while True:
        try:
            remote_ip = socket.gethostbyname(hostname)
        except OSError as sock_error:
            time.sleep(INTERVAL)
            continue
        break
    return remote_ip 



# retrieve local ip addr from outside 
def get_src_ip():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', DST_PORT))
        except OSError as sock_error:
            continue
        break
    return s.getsockname()[0]



# sending socket: SOCK_RAW/IPPROTO_RAW
def send_sock():
    try:
        # SOCK_RAW indicates communication is directly to the network protocols
        # IPPROTO_RAW indicates that the communication is to the IP layer
        # raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        snd_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except OSError as sock_error:
        print ('Create sending socket failed.')
        sys.exit(sock_error.errno)
    return snd_sock



# recving socket: SOCK_RAW/IPPROTO_TCP
def recv_sock():
    try:
        # SOCK_RAW indicates communication is directly to the network protocols
        # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # define ETH_P_IP    0x0800      /* Internet Protocol packet */
        # sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except OSError as sock_error:
        print ('Create receiving socket failed.')
        sys.exit(sock_error.errno)
    return sock



# send packet through given socket
def send_packet(snd_sock, pkt, ip, port):
    while True:
        try:
            snd_sock.sendto(pkt, (ip, port))
        except OSError as sock_send_error:
            print ('Packet sending failed. Retry.')
            continue
        break



# receive packet from recv socket with timeout of MAX_WAIT (60 secs)
# if none result/ retries reached timeout: return False
# else return received packet
# result can be any packet: need to filter
def recv_packet(rcv_sock, buf_len):
    resp = None
    while True:
        try:
            resp = rcv_sock.recvfrom(buf_len)
        except OSError as sock_recv_error:
            continue
        break
    # this could be None
    return resp



# send a packet and receive its response:
# whenever a timeout is reached without ACK packet received
# for orig packet sent, adjust window size and resend the packet
def send_recv_retry(snd_sock, rcv_sock, pkt, ip, port, buf_len, init_wnd):

    send_packet(snd_sock, pkt, ip, port)
    resp = recv_packet(rcv_sock, buf_len)

    # start a timer
    init_time = time.time()

    while not valid_ack(pkt, resp, ip):
        # retry receiving
        resp = recv_packet(rcv_sock, buf_len)
        time.sleep(INTERVAL)
        
        # measure curr time
        curr_time = time.time()
        # retransmit upon timeout
        if curr_time - init_time >= MAX_WAIT:
            #print ('No ACK received within 60 seconds. Retransmit ...')
            # reduce window size to initial value
            new_pkt = adjust_packet_window_size(pkt, init_wnd)
            send_packet(snd_sock, new_pkt, ip, port)
            time.sleep(INTERVAL)
            
            # MAX_WAIT is 360 secs for retransmitting 
            # upon no ACK received
            if curr_time - init_time >= MAX_TIME:
                print ('No data received in 3mins. Exit.')
                sys.exit()
                #break
            else:
                continue

    #print ('Received packet: ')
    #print_packet_info(resp[0])
    return resp



# connect the sending socket to destination server and port
# let the sending socket send SYN and receive SYN-ACK
def connect(snd_sock, rcv_sock, src_ip, dst_ip, port):
    # initialize my TCP sequence number
    my_seq = randrange(RAND_SEED)

    # initialize Acknowledge number and window size
    seq_ack = 0
    # init window is buffer size
    # after response, this would be set to 1 MSS
    wnd = MAX_LEN

    # establish a TCP connection (3-way handshake)
    # 1. send SYN packet
    # flags is a 6-tuple of 0 and 1s: (URG, ACK, PSH, RST, SYN, FIN)
    syn = build_packet(src_ip, dst_ip, my_seq, seq_ack, (0, 0, 0, 0, 1, 0), wnd)
    
    # 2. receive SYN-ACK packet
    syn_ack = send_recv_retry(snd_sock, rcv_sock, syn, dst_ip, port, MAX_LEN, wnd)

    print ('SYN packet: ')
    print_packet_info(syn)
    print ('SYN-ACK packet: ')
    print_packet_info(syn_ack[0])

    # note that the received packet is a 2-tuple: (str, (dst_addr, 0))
    # need to pass only packet str to parsing functions
    return syn_ack



# after connection established, start receiving packets with data
# as responses to the GET packet we sent
# response starts with an:
# 1. ACK or 
# 2. ACK with data 'HTTP/1.1 200 OK'
# note that resp_pkt is a two tuple
# buf_len is the recv length of the socket
# mss is used as unit for window size adjusting
# my_wnd is current window size in use when calling this function
# prev_seq is a list for previous seen sequence number
# data_dict is a (seg no., data) dictionary to store data received
# TODO: is the seq no continuous 
def recv_data(get_pkt, snd_sock, rcv_sock, get_resp_pkt, src_ip, dst_ip, dst_port, buf_len, mss, prev_seq=None, data_dict=None):

    # the ACK for initial GET has been received
    # increment my window size
    my_wnd = inc_cwnd(window_size(get_pkt), mss)
    # get response packet string
    resp = get_resp_pkt[0]
    # print_packet_info(get_resp)
    remote_seq_num = seq_num(resp)
    # prepare an ACK packet to last recvd valid ACK response
    ack_last = resp_packet_to(resp, my_wnd)


    # init retry counter
    recv_retry = 0
    while True:
        # recv a sequence of packets ACKing GET packet
        # with same seq_ack number but diff seq num
        # when receive duplicate response:
        # send ACK for the last valid inorder packet received
        raw_resp = recv_packet(rcv_sock, buf_len)
        recv_retry += 1
        resp = raw_resp[0]

        # filter for packets responding to GET packet sent
        if not valid_ack(get_pkt, raw_resp, dst_ip):
            recv_retry += 1
            if recv_retry == MAX_RETRY:
                # cannot receive, need to retransmit
                # send_packet(snd_sock, ack_last, dst_ip, dst_port)
                # continue
                raw_resp = send_recv_retry(snd_sock, rcv_sock, ack_last, dst_ip, dst_port, buf_len, mss)
            else:
                continue

        
        if valid_ack(get_pkt, raw_resp, dst_ip):
            # received valid ACK:
            # increase window size
            # update current sequence number
            my_wnd = inc_cwnd(my_wnd, mss)
            remote_seq_num = seq_num(resp)

            print ('Received Packet: ')
            print_packet_info(resp)
            
            # update prepared ACK packet
            ack_last = resp_packet_to(resp, my_wnd)
            #send_packet(snd_sock, ack_last, dst_ip, dst_port)

            if is_dup_pkt(raw_resp, prev_seq):
                # this is a retransimission
                # send prepared ACK for last received packet
                send_packet(snd_sock, ack_last, dst_ip, dst_port)
            else:
                if prev_seq != None:
                    record_seq_num(resp, prev_seq)
                if data_dict != None:
                    record_seg_data(resp, data_dict)
                if is_fin_ack(resp):
                    print ('FIN-ACK received.')

                    # handle connection tear down
                    fin_ack = resp_packet_to(resp, 0)
                    final_ack = send_recv_retry(snd_sock, rcv_sock, fin_ack, dst_ip, dst_port, buf_len, mss)
                    break
                continue
        else:
            continue
    print ('Finalized data receiving.')



