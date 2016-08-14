from _socket import *
#ONLY WORKS FOR IPV4 ADDRESSING
__author__ = 'NIKHIL'
import socket
import sys
import struct
import re

def receiveData(s):  # Creation of a raw socket
    try:
        data = s.recvfrom(65565)  # 65565 is the port being used
    except timeout:  # if a timeout error occurs then throw this exception
        data = ''
    except:
        print " AN ERROR HAS OCCURED"
        sys.exc_info()  # This function returns a tuple of three values that give information about the exception that is currently being handled.
    return data[0]  # This is being used as the code run from cmd is unreadle and contains a group of tuples and strings <-->This statement will basically return the first row and the unreadable string

# it gives the time of service - 8bits
def getTOS(data):
    #creating dictionaries for the TOS header

    precedence = {0: "Routine",1: "Priority",2: "Immediate",3: "Flash",4:"Flash Override",5:"CRITIC/ECP",6:"Internetwork control",7:"Network Conttrol"}

    #CRITIC/ECP - stands for critical and emergency processing

    delay = {0:"Normal Delay",1:"Low delay"}
    thoroughput = {0:"Normal thoroughput",1:"High thoroughput"}
    reliability = {0:"Normal reliablity",1:"High reliability"}
    monetary_cost = {0:"Normal monetary cost",1:"High monetary cost"}

    #Parsing specific bits of the TOS

    D = data & 0x10
    D>>=4 # shidting bits by 4
    T = data & 0x8
    T>>=3
    R = data & 0x4
    R>>=2
    M = data & 0x2
    M>>=1

    tabs = '\n\t\t\t'

    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + thoroughput[T] + tabs + reliability[R] + tabs + monetary_cost[M]
    return  TOS



def getflag(data):
    #making dictionaries for flag
    reserve = {0:"0-Reserved bit"}
    flagDF = {0:"0-Fragment if necessary",1:"Dont Fragment"}
    flagMF = {0:"0-Last fragment",1:"More fragment follow this fragmnent"}

    R = data & 0x8000
    R>>=15 # as first bit of flag is 16th bit of IP header
    DF = data & 0x4000
    DF >>=14
    MDF = data & 0x2000
    MDF >>=13

    tabs = '\n\t\t\t'
    flag = reserve[R]+ tabs + flagDF[DF] +tabs + flagMF[MDF]
    return  flag

def getprotocol(Protocolnum):
    protocolfile = open('protocol.txt','r')  #this is used to read the file that contains all the protocols
    protocoldata = protocolfile.read()
    protocol = re.findall(r'\n' + str(Protocolnum) + ' (?:.)\n',protocoldata)  # this line searches for the specific protocol from the protocoldata
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '') #replace any new line with null string
        protocol = protocol.replace(str(Protocolnum),'') # replaces the number from the protocol
        protocol = protocol.lstrip()
        return protocol
    else:
        return "NO SUCH PROTOCOL FOUND"


HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

data=receiveData(s)  # calling the raw socket fuction
unpackedData = struct.unpack('BBHHHBBH4s4s', data[:20])

# The string BBHHHBBH4s4s is used for a specific unpacking task
# B->unsigned char which will unpack first 8 bits(1 byte) of ipv4 address
# H - will take 16 bits(2 byte) i.e the first H will unpack the services portion and so on
# s-> char[] which is a string
version_IHL = unpackedData[0] # calculate the internet header length
version = version_IHL >> 4 # Shifting the version header by 4 so that we get IHL
IHL = version_IHL & 0xf    # Anding the value of IHL with 00011111
TOS = unpackedData[1]
Total_length = unpackedData[2]
ID = unpackedData[3]
flag = unpackedData[4]
fragment_offset = unpackedData[4] & 0x1FFF
ttl = unpackedData[5] # used to calculate lifetime of the datagram
Protocolnum = unpackedData[6]
checksum = unpackedData[7]
sourceaddress = inet_ntoa(unpackedData[8]) #this converts packed ipv4 to the normal form
destinationaddress = inet_ntoa(unpackedData[9]) #this converts the ipv4 addresss to its normal form with dots

#PRINTING ALL THE DATA WE HAVE PARSED
print "A PACKET WITH A SIZE %s HAS BEEN RECOVERED" %Total_length
print "THE RAW DATA RECEIVED BY THE GET HOST " +data
print "\n PARSED DATA "
print "VERSION : \t\t" +str(version)
print "Internet Header Length :\t\t" +str(IHL*4) + "bytes"
print "TYPE OF SERVICE : \t\t" +getTOS(TOS)
print "\t\t TOTAL LENGTH : " +str(Total_length)
print "ID \t\t\t" +str(hex(ID)) + '(' + str(ID) + ')'
print "Flags \t\t\t" + getflag(flag)
print "FRAGMENT OFFSET \t\t" + str(fragment_offset)
print "TIME TO LEAVE : \t\t" +str(ttl)
print "PROTOCOL : \t\t" + getprotocol(Protocolnum)
print "CHECKSUM : \t\t " +str(checksum)
print "SOURCE ADDRESS : \t\t" + str(sourceaddress)
print "DESTINATION ADDRESS \t\t" +str(destinationaddress)
print(unpackedData)
# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

