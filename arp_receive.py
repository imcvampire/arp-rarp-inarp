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
			ethernet_type = binascii.hexlify(ethernet_layer[2]).decode('ascii')
			if ethernet_type == "0806" or ethernet_type == "8035":
				
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
				
				# Ethernet Layer
				dest_mac   = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", ethernet_layer[0])
				source_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", ethernet_layer[1])
				
				# ARP Layer
				hardware_type = binascii.hexlify(arp_layer[0]).decode('ascii')
				protocol_type = binascii.hexlify(arp_layer[1]).decode('ascii')
				hardware_size = binascii.hexlify(arp_layer[2]).decode('ascii')
				protocol_size = binascii.hexlify(arp_layer[3]).decode('ascii')
				opcode        = binascii.hexlify(arp_layer[4]).decode('ascii')
<<<<<<< HEAD
				source_mac    = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[5])
				source_ip     = socket.inet_ntoa(arp_layer[6])
				dest_mac      = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[7])
=======
				source_mac    = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[0])
				source_ip     = socket.inet_ntoa(arp_layer[6])
				dest_mac      = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",ethernet_layer[0])
>>>>>>> 2bcd8764238f57daa994e3cbbb467a3cdbedee13
				dest_ip       = socket.inet_ntoa(arp_layer[8])
				
				
				# Packet Information
				#
				#
				#
				#
				print()
				
				count = count + 1
				print("Packet {0}".format(count))
				print()
				
				print("****************_ETHERNET_FRAME_****************")
				
				print("Dest MAC        :", dest_mac)
				print("Source MAC      :", source_mac)
				print("Type            :", ethernet_type)
				
				print("******************_ARP_HEADER_******************")
				
				print("Hardware type   :", hardware_type)
				print("Protocol type   :", protocol_type)
				print("Hardware size   :", hardware_size)
				print("Protocol size   :", protocol_size)
				print("Opcode          :", opcode)
				print("Source MAC      :", source_mac)
				print("Source IP       :", source_ip)
				print("Dest MAC        :", dest_mac)
				print("Dest IP         :", dest_ip)
				
				print("*************************************************")
				
				print()
				
				# if ethernet_type == "0806":
			
		except:
			pass