"""
module 01: parse input
this module focuses on reading and parsing input data from a file.
ensuring that a specific format is maintained for further processing.
the expected output are valid domain name and ip address of the inputted data.
and stored it to a database.
"""
import sys, os, tldextract, ipaddress, socket, datetime
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.db_utils import *
input_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test-data', 'input.txt')

with open(input_file, 'r') as inp:
    lines = list(line for line in (l.strip() for l in inp) if line)

def define_type(input: str):
    try:
        ipaddress.ip_address(input)
        return 'ip'
    except ValueError:
        return 'domain'

def process_hostname(input: str):
    ext = tldextract.extract(input)
    fqdn = ext.fqdn
    try:
        ipset = socket.getaddrinfo(fqdn, 80)
    except socket.gaierror:
        ipset = []
    ips = {item[4][0] for item in ipset}
    for i in ips:
        cur_time = datetime.datetime.now()
        print(i, input, cur_time)

process_hostname("")
# for l in lines:
#     l = l.strip()
#     if not l:
#         continue
#     if define_type(l) == 'domain':
#         result = process_hostname(l)
#         if result:
#             print(result)