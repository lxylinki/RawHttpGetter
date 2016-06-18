#!/usr/bin/python
from math import floor


# covert a decimal flag value into binary 
def restore_flag(dec_val):
    # NS  bit
    # ns = int(floor(dec_val / 256))
    # remain = dec_val - (256 * ns)

    # CWR bit
    cwr = int(floor(dec_val / 128))
    remain = dec_val - (128 * cwr)
    
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

    return (cwr, ece, urg, ack, psh, rst, syn, fin)


print (80, restore_flag(80))
print (24, restore_flag(24))
print (18, restore_flag(18))
print (12, restore_flag(12))
