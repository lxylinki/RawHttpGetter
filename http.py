#!/usr/bin/python

from collections import OrderedDict
from string import Template
from urlparse import urlparse



# HTTP GET format for page downloading
GET_CMD = 'GET $path HTTP/1.1\n'
HOST = 'Host: $host\n'
GET_TEMP = GET_CMD + HOST + '\n'


# returns (host, path) from a given url
def parse_url(url):
    parsed = urlparse(url)
    return parsed.netloc, parsed.path


# user data string
def build_GET(url):
    url_host, url_path = parse_url(url)
    GET = Template(GET_TEMP).substitute(path = url_path, host = url_host)
    #return GET.encode(encoding='utf-8')
    return GET


# write data dictionary to file
def write_http_resp(data_dict, file_name):
    ordered_data = OrderedDict(sorted(data_dict.items()))
    with open(file_name, 'ab') as file:
        for seq_no in ordered_data:
            file.write(ordered_data[seq_no])


# write html to file
def write_html(data_dict, file_name):
    ordered_data = OrderedDict(sorted(data_dict.items()))
    full_resp = ''.join( ordered_data[seq_no] for seq_no in ordered_data )
    html = full_resp.split('\r\n\r\n')[1]
    with open(file_name, 'w') as file:
        file.write(html)





