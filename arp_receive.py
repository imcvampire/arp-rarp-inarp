import socket
import struct
import binascii
import netifaces as ni



if __name__ == "__main__":
	
	count = 0
	
	# RawSocket
	#
	#
	rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	
	while True:
		try:
			# Receive packet
			#
			#
			#
			packet = rawSocket.recvfrom(2048)
			
			
			# Unpack Ethernet header
			#
			#
			#			
			ethernet_header = packet[0][0:14]
			ethernet_layer = struct.unpack("!6s6s2s", ethernet_header)
			
			# ARP packet filter
			#
			#
			#
			ethernet_type = ethernet_layer[2]
			if ethernet_type != binascii.unhexlify("0806"):
				continue
			
			# Unpack ARP header
			#
			#
			#
			arp_header = packet[0][14:42]
			arp_layer = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
			
			# Decode packet
			#
			#
			#
			print()
			
			count = count + 1
			print("Packet {0}".format(count))
			print()
			
			print("****************_ETHERNET_FRAME_****************")
			print("Dest MAC        :", "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[0]))
			print("Source MAC      :", "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[0]))
			print("Type            :", binascii.hexlify(ethernet_type).decode('ascii'))
			print("******************_ARP_HEADER_******************")
			print("Hardware type   :", binascii.hexlify(arp_layer[0]).decode('ascii'))
			print("Protocol type   :", binascii.hexlify(arp_layer[1]).decode('ascii'))
			print("Hardware size   :", binascii.hexlify(arp_layer[2]).decode('ascii'))
			print("Protocol size   :", binascii.hexlify(arp_layer[3]).decode('ascii'))
			print("Opcode          :", binascii.hexlify(arp_layer[4]).decode('ascii'))
			print("Source MAC      :", "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[0]))
			print("Source IP       :", socket.inet_ntoa(arp_layer[6]))
			print("Dest MAC        :", "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[0]))
			print("Dest IP         :", socket.inet_ntoa(arp_layer[8]))
			print("*************************************************")
			
			print()
			
			
		except:
			pass