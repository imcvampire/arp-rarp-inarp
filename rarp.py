#!/usr/bin/python3

import sys
import arp_core
import socket
import struct
import binascii
import time
import threading
import argparse



def main():
	# Create Receive Thread
	#
	#
	receive_thread = threading.Thread(target = receiver)
	receive_thread.start()
	
	# Send ARP Request Packet
	#
	#
	arp_core.SendRArpRequestPacket()
	
	# Join Thread
	#
	#
	receive_thread.join()
		
	return


def receiver():
	
	# Receive ARP Reply
	#
	# RawSocket
	#
	rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	
	try:
		timeout = time.time() + 0.2
		
		while True:
			try:
				# Receive packet
				#
				#
				packet = rawSocket.recvfrom(2048)
				
				
				# Unpack Ethernet header
				#
				#		
				ethernet_header = packet[0][0:14]
				ethernet_layer = struct.unpack("!6s6s2s", ethernet_header)
				
				# ARP packet filter
				#
				#
				ethernet_type = binascii.hexlify(ethernet_layer[2]).decode('ascii')
				if ethernet_type == "0806":
					
					# Unpack ARP header
					#
					arp_header = packet[0][14:42]
					arp_layer = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
					
					# Decode packet
					#
					#
					#
					# Ethernet Layer
					dest_mac   = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", ethernet_layer[0])
					source_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", ethernet_layer[1])
					
					# ARP Layer
					opcode        = binascii.hexlify(arp_layer[4]).decode('ascii')
					sender_mac    = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",arp_layer[5])
					sender_ip     = socket.inet_ntoa(arp_layer[6])
					target_mac    = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",arp_layer[7])
					target_ip     = socket.inet_ntoa(arp_layer[8])
					
					
					# Display output
					#
					#
					if opcode == "0004":
						print()
						print("=================================================")
						print("IP                     MAC")
						print()
						print("{0:<15}        {1}".format(target_ip, target_mac))
						print("=================================================")
						print()
						break
			
				if time.time() > timeout:
					print()
					print("=================================================")
					print("Request Timeout!")
					print("=================================================")
					print()
					break
			except Exception as e:
				print()
				print(e)
				print()
				
		#
		#
		#
		# while true: receive packet	
			
	except KeyboardInterrupt:
		print()
		print("KeyboardInterrupt!")
		
	return
	


if __name__ == "__main__":
	main()