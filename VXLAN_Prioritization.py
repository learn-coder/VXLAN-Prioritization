#!/usr/bin/python


#Declarations
from socket import * 
from vxlan_project_new import VXLAN
import struct
import time


#IP header 1:
version_length = "\x45"
dscp = "\x00"
total_length = "\x00\x46"
iden = "\x04\xd2"
frag_off = "\x00\x00"
ttl = "\x7f"
protocol = "\x11"
checksum = "\x36\xd6"
src_ip = "\x0A\x00\x00\x01"
dst_ip = "\x0A\x00\x00\x02"
ip_header_1 = version_length+dscp+total_length+iden+frag_off+ttl+protocol+checksum+src_ip+dst_ip
ip_header_1_hex  = "".join("{:02x}".format(ord(c)) for c in ip_header_1) 
global ip_header_1_byte
ip_header_1_byte = bytearray(ip_header_1_hex)
    

#IP header 2:
version_length1 = "\x45"
dscp1 = "\x00"
total_length1 = "\x00\x14"
iden1 = "\x04\xd2"
frag_off1 = "\x00\x00"
ttl1 = "\x7f"
protocol1 = "\x00"
checksum1 = "\x37\x17"
src_ip1 = "\x0A\x00\x00\x01"
dst_ip1 = "\x0A\x00\x00\x02"
ip_header_2 = version_length1+dscp1+total_length1+iden1+frag_off1+ttl1+protocol1+checksum1+src_ip1+dst_ip1
ip_header_2_hex  = "".join("{:02x}".format(ord(c)) for c in ip_header_2) 


#UDP header :
udp = "\x23\x45\x23\x45\x00\x32\x00\x00"
udp_hex  = "".join("{:02x}".format(ord(c)) for c in udp) 
trailer = "\x00"


#Socket creation and binding
s = socket(AF_PACKET, SOCK_RAW,4)
s.bind(("eth0", 0))


#Splitting the VXLAN Frame
def split_frame(vxlan_packet_hex):
    vnid=vxlan_packet_hex[8:14]
    return vnid


#Setting priority to the VXLAN header
def set_priority(vnid,vxlan_packet_hex):
    print "VXLAN priority setup"
    global byte_vxlan_packet
    admin_vnid = "0003e8".decode("hex")
    admin_vnid1 = "0007d0".decode("hex")
    admin_vnid2 = "000bb8".decode("hex")
    
    #IF VNID matches with the VXLAN1
    if vnid == admin_vnid:
        byte_vxlan_packet = bytearray(vxlan_packet_hex)
        byte_vxlan_packet[3] = "1"
        byte_vxlan_packet[4]  = "c" 
        byte_vxlan_priority = byte_vxlan_packet.decode("hex")  
        return byte_vxlan_priority
    
    #IF VNID matches with the VXLAN2
    elif vnid == admin_vnid1:
        byte_vxlan_packet = bytearray(vxlan_packet_hex)
        byte_vxlan_packet[3] = "1"
        byte_vxlan_packet[4]  = "0" 
        byte_vxlan_priority = byte_vxlan_packet.decode("hex")  
        return byte_vxlan_priority
    
    #IF VNID matches with the VXLAN3
    else:
        byte_vxlan_packet = bytearray(vxlan_packet_hex)
        byte_vxlan_packet[3] = "0"
        byte_vxlan_packet[4]  = "0" 
        byte_vxlan_priority = byte_vxlan_packet.decode("hex")  
        return byte_vxlan_priority


#Setting IP priority according to the VXLAN priority 
def change_ip_priority(ip_header_1_byte):
    #Priority setup for VXLAN1
    if byte_vxlan_packet[3] == 49 and byte_vxlan_packet[4] == 99 :
        print "Success packet from VXLAN 1!!!!!"
        ip_header_1_byte[2] = "B"
        ip_header_1_byte[3] = "8"
        ip_header_1_priority_set = ip_header_1_byte.decode("hex")  
        return ip_header_1_priority_set
    
    #Priority setup for VXLAN2
    elif byte_vxlan_packet[3] == 49 and byte_vxlan_packet[4] == 48 :
        print "Success packet from VXLAN 2!!!!!"
        ip_header_1_byte[2] = "3"
        ip_header_1_byte[3] = "0"
        ip_header_1_priority_set = ip_header_1_byte.decode("hex")  
        return ip_header_1_priority_set
    
    #Priority setup for VXLAN3
    else:	
        print "Success packet from VXLAN 3!!!!!"
        ip_header_1_byte[2] = "0"
        ip_header_1_byte[3] = "0"
        ip_header_1_priority_set = ip_header_1_byte.decode("hex")  
        return ip_header_1_priority_set


def ethernet():
    #Ethernet frame from VXLAN1
    src_addr = "\x01\x02\x03\x04\x05\x06"
    dst_addr = "\x01\x02\x03\x04\x05\x06"
    ethertype = "\x08\x00"
    frame = (src_addr+dst_addr+ethertype)
    frame_hex = "".join("{:02x}".format(ord(c)) for c in frame) 
    conv_frame = frame_hex.decode("hex")
    s.send(frame)
    
    baseclass(frame)
     
    #Ethernet frame from VXLAN2           
    src_addr1 = "\x07\x08\x09\x10\x11\x12"
    dst_addr1 = "\x07\x08\x09\x10\x11\x12"
    ethertype1 = "\x08\x00"
    frame1 = (src_addr1+dst_addr1+ethertype1)
    frame_hex1 = "".join("{:02x}".format(ord(c)) for c in frame1) 
    conv_frame1 = frame_hex1.decode("hex")
    s.send(frame1)
    baseclass(frame1)

    #Ethernet frame from VXLAN3           
    print 'E3'
    src_addr2 = "\x13\x14\x15\x16\x17\x18"
    dst_addr2 = "\x13\x14\x15\x16\x17\x18"
    ethertype2 = "\x08\x00"
    frame2 = (src_addr2+dst_addr2+ethertype2)
    frame_hex2 = "".join("{:02x}".format(ord(c)) for c in frame2) 
    conv_frame2 = frame_hex2.decode("hex")
    s.send(frame2)
    baseclass(frame2)

#Main class Sending the packets authenticity and sending packet onto the socket
def baseclass(frame):
    
    check = "\x01\x02\x03\x04\x05\x06"
    check_hex = "".join("{:02x}".format(ord(c)) for c in check) 
    check1 = "\x07\x08\x09\x10\x11\x12"
    check1_hex = "".join("{:02x}".format(ord(c)) for c in check1) 
    check2 = "\x13\x14\x15\x16\x17\x18"
    check2_hex = "".join("{:02x}".format(ord(c)) for c in check2) 
    
    frame_hex = "".join("{:02x}".format(ord(c)) for c in frame) 
    source_mac = frame_hex[0:12]
    
    #VXLAN frame creation and respective VNID association
    if source_mac == check_hex:
        vx = VXLAN(frame,None,1000)
        vxlan_packet =vx.__str__()
        vxlan_packet_hex  = "".join("{:02x}".format(ord(c)) for c in vxlan_packet) 
    
    elif source_mac == check1_hex:
        vx = VXLAN(frame,None,2000)
        vxlan_packet =vx.__str__()
        vxlan_packet_hex  = "".join("{:02x}".format(ord(c)) for c in vxlan_packet) 
        
    else:
        vx = VXLAN(frame,None,3000)
        vxlan_packet =vx.__str__()
        vxlan_packet_hex  = "".join("{:02x}".format(ord(c)) for c in vxlan_packet) 
      

    #VNID dissection
    vnid_hex = split_frame(vxlan_packet_hex)
    vnid_string  = vnid_hex.decode("hex")#"".join("{:02x}".format(ord(c)) for c in vnid_string) 
    
    #VXLAN packet setup function call
    byte_vxlan_priority= set_priority(vnid_string,vxlan_packet_hex)

    #IP header priority setup fucntion call
    ip_header_1_priority_set=change_ip_priority(ip_header_1_byte)
    print "ip_header_1_priority_set is  :"
    print ip_header_1_priority_set 


    #Final packet creation
    final_packet = frame+ip_header_1_priority_set+udp+byte_vxlan_priority+ip_header_2+trailer
    final_packet_hex= "".join("{:02x}".format(ord(c)) for c in final_packet) 
    
    #Sending the packet on to the socket
    s.send(final_packet)


ethernet()
