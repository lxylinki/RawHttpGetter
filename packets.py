#!/usr/bin/python
from consts import *
from ip_tcp import *
from math import floor



# given an IP packet str, print details, return critical info
def inspect_packet(packet_str):
    # start decode
    # 1. seperate and decode IP header
    ip_header_raw = packet_str[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header_raw)
    s_addr = socket.inet_ntoa(iph[8])

    #print('\n-------------------------Packet Info Start-----------------------')
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF


    # byte length of IP header
    iph_length = ihl * 4
    ip_tos = iph[1]
    ip_id = iph[3]
    ip_offset = iph[4]

    ip_flag = ip_offset >> 13
    # print('ip_flag is: ' + str(ip_flag))

    ttl = iph[5]
    protocol = iph[6]
    ip_chksm = iph[7]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    #print ('IP Version : ' + str(version) + '\nIP Header Length : ' + str(iph_length) + '\nIP Fragment Offset : ' + str(ip_offset) + '\nIP Flag : ' + str(ip_flag) + '\nTime To Live : ' + str(ttl) + '\nProtocol : ' + str(protocol) + '\nIP Checksum :' + str(ip_chksm) + '\nFrom Address : ' + str(s_addr) + '\nTo Address : ' + str(d_addr) + '\n\n')
     


    # 2. seperate and decode TCP header
    tcp_header_raw = packet_str[iph_length:iph_length + 20]
    tcph = unpack('!HHLLBBHHH' , tcp_header_raw)
    tcp_source_port = tcph[0]
    tcp_dest_port = tcph[1]
    tcp_sequence = tcph[2]
    tcp_acknowledgement = tcph[3]
    tcp_doff_reserved = tcph[4]
    tcp_tcph_length = (tcp_doff_reserved >> 4) * 4
    tcp_flags = tcph[5]
    
    # print(tcp_flag_bits)
    tcp_window = tcph[6]
    tcp_chksm = tcph[7]
    tcp_urgptr = tcph[8]
     
    # 3. seperate data part
    data = ''
    header_size = iph_length + tcp_tcph_length
    data_size = len(packet_str) - header_size
    if data_size > 0:
        data = packet_str[header_size:]
    
    tcp_mss = -1
    if (tcp_tcph_length > 20):
        option = packet_str[(iph_length + 20): header_size]
        if len(option) == 4:
            # Max Segment Size encoded here: 
            # 00000010 : 00000100 : Max Segment Size
            # print('Max Segment Size: ' + str(get_mss(option)))
            tcp_mss = get_mss(option)
    
    #print ('\nTCP header length : ' + str(tcp_tcph_length) + '\nSource Port : ' + str(tcp_source_port) + '\nDest Port : ' + str(tcp_dest_port) + '\nTCP Sequence Number : ' + str(tcp_sequence) + '\nAcknowledgement : ' + str(tcp_acknowledgement) + '\nTCP Data Offset : ' + str(tcp_doff_reserved) + '\nTCP Flags : ' + str(tcp_flags) + '\nTCP Advertised Window Size : ' + str(tcp_window) + '\nTCP Checksum : ' + str(tcp_chksm) + '\nTCP Urgent Pointer : ' + str(tcp_urgptr) + '\nTCP Max Segment Size : ' + str(tcp_mss) + '\nTCP Segment Data : ' + data) 

    #print('------------------------------Packet Info End---------------------------')
    # all info needed to return
    # [source ip, destination ip, packet size, header size, 
    #  ip fragment offset, ip checksum, 
    #  tcp data offset, tcp sequence number, tcp window size, tcp checksum, tcp acknowledgement number]
    info_list = [s_addr, d_addr, len(packet_str), header_size, \
            ip_offset, ip_chksm, tcp_flags, tcp_sequence, \
            tcp_window, tcp_chksm, tcp_acknowledgement, tcp_mss]

    #print ('No. of Packet Info Items: ' + str(len(info_list)))
    if data_size > 0:
        # print ('--------------' + data)
        # this would return none as the append function return value
        # info_list = info_list.append(data)
        info_list.append(data)
        #print ('No. of Packet Info Items (with data): ' + len(info_list))
    return info_list


# get src ip address
def get_src(pkt):
    return inspect_packet(pkt)[0]

# get dst ip address
def get_dst(pkt):
    return inspect_packet(pkt)[1]

# get ip checksum of a packet
def ip_checksum(pkt):
    return inspect_packet(pkt)[5]

# get tcp checksum of a packet
def tcp_checksum(pkt):
    return inspect_packet(pkt)[9]

# get sequence number of a packet
def seq_num(pkt):
    return inspect_packet(pkt)[7]

# get acknowledge number of a packet
def ack_num(pkt):
    return inspect_packet(pkt)[10]

# get window size advertised in a packet
def window_size(pkt):
    return inspect_packet(pkt)[8]


# returns data iff the packet carries data
# otherwise return false
def has_data(pkt):
    pkt_info = inspect_packet(pkt)
    if len(pkt_info) == 13:
        return pkt_info[12]
    else:
        return False


# returns max segment size of a packet
def get_mss(pkt):
    return inspect_packet(pkt)[11]


# get IP flag of a packet
def get_ip_flag(pkt):
    # start decode
    # 1. seperate and decode IP header
    ip_header_raw = pkt[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header_raw)
    ip_offset = iph[4]
    ip_flag = ip_offset >> 13
    return ip_flag


# get TCP flag bit of a packet
def get_tcp_flag(pkt):
    dec_flag = inspect_packet(pkt)[6]
    return restore_flag(dec_flag)


# true iff the ACK and FIN bits in the packet set to 1
def is_fin_ack(pkt):
    if get_tcp_flag(pkt) == (0, 1, 1, 0, 0, 1):
        return True
    elif get_tcp_flag(pkt) == (0, 1, 0, 0, 0, 1):
        return True
    else:
        return False



# display summary info of a packet
def print_packet_info(pkt):
    all_info = inspect_packet(pkt)

    s_addr = all_info[0]
    d_addr = all_info[1]
    header_size = all_info[3]
    ip_offset = all_info[4]
    ip_chksm = all_info[5]

    #tcp_doff_reserved = all_info[6]
    tcp_flag_val = all_info[6]
    tcp_flags = restore_flag(tcp_flag_val)

    #tcp_flags = tcp_flag_val
    tcp_sequence = all_info[7]
    tcp_window = all_info[8]
    tcp_chksm = all_info[9]
    tcp_acknowledgement = all_info[10]
    tcp_mss = all_info[11]

    # packet has data
    if len(all_info) == 13:
        data = all_info[12]

    print('------------------------------Packet Summary----------------------------')
    print(s_addr + ' --------> ' + d_addr)
    #print('Packet Length: ' + str(len(pkt)))
    #print('Header Length: ' + str(header_size))
    #print('IP Fragment Offset: ' + str(ip_offset))
    print('IP Checksum: ' + str(ip_chksm))
    #print('TCP Data Offset: ' + str(tcp_doff_reserved))
    #print('TCP Flag Value: ' + str(tcp_flag_val))
    print('TCP Flag Bits: \n(urg, ack, psh, rst, syn, fin)')
    print(tcp_flags)
    print('TCP Window Size: ' + str(tcp_window))
    print('TCP Checksum : ' + str(tcp_chksm))
    print('TCP Sequence No.: ' + str(tcp_sequence))
    print('TCP Acknowledge No.: ' + str(tcp_acknowledgement))
    if tcp_mss > 0:
        print('TCP Max Segment Size: ' + str(tcp_mss))
    if len(all_info) == 13:
        print('TCP Segment Data of Len {}:\n\n'.format(len(data)) + data)
    print('------------------------------------------------------------------------')
    print('\n')


# src_ip, dst_ip, seq_num, seq_ack, tcp_flags, wnd which is computed from (current congestion window size, remote advertised window size), bytes data
# my advertised window size is min (current congestion window size, recved adv window size)
def build_packet(src, dst, seq, seq_ack, flags, wnd, data=None):
    if data == None:
        packet = IP_header(src, dst) + \
                 TCP_header(src, dst, seq, seq_ack, flags, wnd)
    else:
        packet = IP_header(src, dst) + \
                 TCP_header(src, dst, seq, seq_ack, flags, wnd, data) + data
    return packet



# given a sent packet and a received packet
# which could be empty
# returns true iff the received packet is a 
# correct ACK to the sent one
# recvd_pkt is the raw packet received
def valid_ack(sent_pkt, recvd_pkt, remote_ip):
    if recvd_pkt is None:
        return False

    elif len(recvd_pkt) == 0:
        return False

    elif not my_packet(recvd_pkt, remote_ip):
        return False

    elif seq_ack_match(sent_pkt, recvd_pkt):
        return True

    else:
        return False



# given a sent packet and a received packet
# which belongs to this program
# verify if the received packet is the ACK
# to the sent packet
def seq_ack_match(sent_pkt, recvd_pkt):

    #print ('---------------------------------------')
    #print ('Sent Seq No.: ' + str(seq_num(sent_pkt)))
    #print ('Rcvd Ack No.: ' + str(ack_num(recvd_pkt[0])))
    #print ('---------------------------------------')

    # if the packet does not contain data
    if has_data(sent_pkt) == False:
        # when no data contained in packet:
        # ack_num is (seq_num + 1)
        if (seq_num(sent_pkt) + 1) == ack_num(recvd_pkt[0]):
            return True
        else:
            return False
    else:
        # this packet contains data
        data = has_data(sent_pkt)
        data_len = len(data)

        # print ('Sent packet with data of length {}'.format(data_len))
        # print (data)

        # when data presents in packet
        # ack_num should be (seq_num + len)
        if (seq_num(sent_pkt) + data_len) == ack_num(recvd_pkt[0]):
            return True
        else:
            return False
             


# rebuild an almost identical packet with reduced window size
# this is for retransmit
def adjust_packet_window_size(pkt, init_wnd):
    pkt_info = inspect_packet(pkt)
    
    src_ip = pkt_info[0]
    dst_ip = pkt_info[1]
    seq_no = pkt_info[7]
    seq_ack = pkt_info[10]

    # decimal -> 0-1 tuple
    flag_val = pkt_info[6]
    tcp_flag = restore_flag(flag_val)
    
    # adv_wnd = pkt_info[8]
    # reset awnd to 1 MSS
    awnd = init_wnd

    data = ''
    if len(pkt_info) == 13:
        data = pkt_info[12]
    if len(data) > 0:
        new_pkt = build_packet(src_ip, dst_ip, seq_no, seq_ack, tcp_flag, awnd, data)
    else:
        new_pkt = build_packet(src_ip, dst_ip, seq_no, seq_ack, tcp_flag, awnd)
    return new_pkt



# ACK can be accumulative
# build a response ACK packet for a valid received packet

# given:
# a received packet string part
# current congestion window size: 
# an indicator of network load on my side
def resp_packet_to(recvd_pkt, cwnd):
    pkt_info = inspect_packet(recvd_pkt)

    # switch this when respond
    orig_src_ip = pkt_info[0]
    orig_dst_ip = pkt_info[1]

    my_src_ip = orig_dst_ip
    my_dst_ip = orig_src_ip
    orig_seq_no = pkt_info[7]

    # next sequence number the remote side 
    # is expecting
    orig_seq_ack = pkt_info[10]
    my_seq = orig_seq_ack

    # decimal -> 0-1 tuple
    # flag_val = pkt_info[6]
    # tcp_flag = restore_flag(flag_val)

    awnd = pkt_info[8]
    wnd = min(cwnd, awnd)

    data = None
    data_len = 0

    # default ack
    my_seq_ack = orig_seq_no + 1

    # if received packet carries data
    # include data length in seq_ack
    if len(pkt_info) == 13:
        data = pkt_info[12]
        data_len = len(data)
    if data_len > 0:
        my_seq_ack = orig_seq_no + data_len

    # set ACK flag
    my_tcp_flag = (0, 1, 0, 0, 0, 0)
    # respond to FIN-ACK with a FIN-ACK
    if is_fin_ack(recvd_pkt):
        my_tcp_flag = (0, 1, 0, 0, 0, 1)

    new_pkt = build_packet(my_src_ip, my_dst_ip, my_seq, my_seq_ack, my_tcp_flag, wnd)
    return new_pkt


# covert a decimal flag value into binary 
def restore_flag(dec_val):
    # NS  bit
    ns = int(floor(dec_val / 256))
    remain = dec_val - (256 * ns)

    # CWR bit
    cwr = int(floor(remain / 128))
    remain -= (128 * cwr)
    
    # ECE bit 
    ece = int(floor(remain / 64))
    remain -= (64 * ece)

    # URG bit
    urg = int(floor(remain / 32))
    remain -= (32 * urg)
    
    # ACK bit
    ack = int(floor(remain / 16))
    remain -= (16 * ack)

    # PSH bit
    psh = int(floor(remain / 8))
    remain -= (8 * psh)

    # RST bit
    rst = int(floor(remain / 4))
    remain -= (4 * rst)

    # SYN bit
    syn = int(floor(remain / 2))
    remain -= (2 * syn)

    # FIN bit
    fin = int(floor(remain / 1))
    remain -= (1 * fin)
    
    '''
    print('URG ' + str(urg) + \
          ', ACK ' + str(ack) + \
          ', PSH ' + str(psh) + \
          ', RST ' + str(rst) + \
          ', SYN ' + str(syn) + \
          ', FIN ' + str(fin))
    '''
    return (urg, ack, psh, rst, syn, fin)



# given a received packet:
# return True iff it is for this prog
# by verify following parameters
# 1. remote ip
# 2. src port
# 3. dest port
def my_packet(resp_pkt, remote_ip):
    raw_pkt = resp_pkt[0]
    ip_header_raw = raw_pkt[0:20]

    iph = unpack('!BBHHHBBH4s4s', ip_header_raw)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    
    tcp_header_raw = raw_pkt[iph_length:iph_length + 20]
    tcph = unpack('!HHLLBBHHH' , tcp_header_raw)
    s_addr = socket.inet_ntoa(iph[8])
    source_port = tcph[0]
    dest_port = tcph[1]

    if (s_addr != remote_ip):
        return False
    elif (source_port != DST_PORT):
        return False
    elif (dest_port != SRC_PORT):
        return False
    else:
        return True



# get MSS from TCP option field with Max Segment Size(MSS)
def get_mss(opt):
    # this is a list of int byte value with 4 items:
    # [Kind, Length, MSS_upper_8, MSS_lower_8]
    loint = map(ord, opt)
    # concate full MSS
    mss = (loint[2] << 8) + loint[3]
    return mss



# convert a string into a dash seperated hex string
def str_to_hex(str):
    res = ''
    length = len(str)
    for i in range(length):
        if i == (length-1):
            res += ('%.2x' % i)
        else:
            res += ('%.2x:' % i)
    return res



# convert a string into a dash seperated binary string
def str_to_binary(str):
    res = ''
    lobin = map(bin, bytearray(str))
    #print(lobin)
    length = len(lobin)
    for i in range(length):
        if i == (length-1):
            res += lobin[i]
        else:
            res += lobin[i] + ':'
    return res



# if a packet is a dup?: 
# 1. tcp sequence number
# (2. tcp ack number)
# (3. tcp header checksum)
# dup packet should be ignored
def is_dup_pkt(recvd_pkt, prev_seq_list):
    if seq_num(recvd_pkt[0]) in prev_seq_list:
        return True
    else:
        return False



# increment congestion window size by 1 mss
# upper bounded by 1000 mss
def inc_cwnd(cwnd, mss):
    if (cwnd + mss) >= MAX_CWND * mss:
        return MAX_CWND * mss
    else:
        return cwnd + mss



# store sequence number of packet resp to prev_seq list
def record_seq_num(resp, prev_seq):
    # store sequence number to a list
    k = seq_num(resp)
    prev_seq.append(k)
    #print (prev_seq)



# store (sequence number, data) of packet resp
# to data_dict dictionary 
# returns the length of data
def record_seg_data(resp, data_dict):
    # store sequence number and segment data as (key, value) pair into the given data dictionary, an empty string is used when no data presents
    k = seq_num(resp)
    v = has_data(resp)
    if v == False:
        v = ''
    data_dict[k] = v
    #print (k, v)
    #print (data_dict)


