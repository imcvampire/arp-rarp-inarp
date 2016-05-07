import socket
import netifaces as ni
import struct
import binascii



# Enumerate
#
#
#
class Type:
	Arp = bytes.fromhex("0806")
	RArp = bytes.fromhex("8035")

class HardwareType:
	Ethernet = bytes.fromhex("0001")

class ProtocolType:
	IPv4 = bytes.fromhex("0800")

class HardwareSize:
	MAC = bytes.fromhex("06")

class ProtocolSize:
	IPv4 = bytes.fromhex("04")
	IPv6 = bytes.fromhex("06")

class Opcode:
	ArpRequest   = bytes.fromhex("0001")
	ArpReply     = bytes.fromhex("0002")
	RArpRequest  = bytes.fromhex("0003")
	RArpReply    = bytes.fromhex("0004")
	InArpRequest = bytes.fromhex("0008")
	InArpReply   = bytes.fromhex("0009")



# Methods
#
#
#
def NetworkInterfaces():
	return ni.interfaces()

def InterfaceMacAddresses(network_interface):
	mac_addresses = []
	try:
		for mac_info in ni.ifaddresses(network_interface)[ni.AF_PACKET]:
			mac_addresses.append(mac_info['addr'])
	except:
		pass
	return mac_addresses

def InterfaceIpAddresses(network_interface, protocol_type): # ni.AF_INET
	ip_addresses = []
	try:
			for ip_info in ni.ifaddresses(network_interface)[protocol_type]:
					ip_addresses.append(ip_info['addr'])
	except:
			pass
	return ip_addresses


# Packet
#
#
#
#

# ARP
def CreateArpRequestPacket(sender_mac_address, sender_ip_address, target_mac_address, target_ip_address):
	
	# Ethernet Layer
	packet  = bytes.fromhex("ff ff ff ff ff ff")
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.Arp
	
	#Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.ArpRequest
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_ip_address)
	
	return packet

def CreateArpReplyPacket(sender_mac_address, sender_ip_address, target_mac_address, target_ip_address):
	# Ethernet Layer
	packet = bytes.fromhex(target_mac_address.replace(":", ""))
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.Arp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.ArpReply
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_ip_address)
	
	return packet



# RARP
def CreateRArapRequestPacket(sender_mac_address, sender_ip_address, target_mac_address, target_ip_address):
	# Ethernet Layer
	packet  = bytes.fromhex("ff ff ff ff ff ff")
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.Arp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.RArpReply
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_ip_address)
	
	return packet

def CreateRArpReplyPacket():
	# Ethernet Layer
	packet = bytes.fromhex(target_mac_address.replace(":", ""))
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.Arp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.RArpReply
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_ip_address)
	
	return packet



# InARP
#
#
#
#
def CreateInArpRequestPacket():
	# Ethernet Layer
	packet = bytes.fromhex(target_mac_address.replace(":", ""))
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.Arp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.RArpReply
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_ip_address)
	
	return
	
def CreateInArpReplyPacket():
	# Ethernet Layer
	packet = bytes.fromhex(target_mac_address.replace(":", ""))
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.Arp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.RArpReply
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_ip_address)
	
	return



# Socket
#
#
#
#
def SendRawPacket(network_interface, packet):
	if network_interface in NetworkInterfaces():
			pass
	else:
			return
	
	sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	sender.bind((network_interface, 0))
	
	sender.send(packet)

def Send(opcode, target_mac_address, target_ip_address):
	if NetworkInterfaces() is None:
			return
	for interface in NetworkInterfaces():
			if InterfaceMacAddresses(interface) is None or interface[0:2] == 'lo':
					continue
			for mac in InterfaceMacAddresses(interface):
					if InterfaceIpAddresses(interface) is None:
							continue
							
					if opcode == 1 or opcode == 2:
						for ip in InterfaceIpAddresses(interface):
							if ip is None:
									continue
							packet = CreateArpPacket(opcode, mac, ip, target_mac_address, target_ip_address)
							SendRawPacket(interface, packet)
					elif opcode == 3 or opcode == 4:
						packet = CreateArpPacket(opcode, mac, "0.0.0.0", target_mac_address, "0.0.0.0")
						SendRawPacket(interface, packet)
					elif opcode == 8 or opcode == 9:
						return
						
	return



# Send Arp
#
#
#
#
def SendArpRequestPacket(target_ip_address):

	# Network interface
	#
	#
	#
	network_interfaces = NetworkInterfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_address is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_ip_addresses = InterfaceIpAddresses(interface, ni.AF_INET)
					
					if interface_ip_address is not None:
						for interface_ip_address in interface_ip_addresses:
							
							# Send ARP Packet
							#
							#
							#
							packet = CreateArpRequestPacket(interface_mac_address, interface_ip_address, "ff ff ff ff ff ff", target_ip_address)
							
							SendRawPacket(network_interface, packet)
							
	return
	
	
def SendRArpRequestPacket():

	# Network interface
	#
	#
	#
	network_interfaces = NetworkInterfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_address is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_ip_addresses = InterfaceIpAddresses(interface)
					
					if interface_ip_address is not None:
						for interface_ip_address in interface_ip_addresses:
							
							# Send ARP Packet
							#
							#
							#
							packet = CreateRArpRequestPacket(interface_mac_address, interface_ip_address, "ff ff ff ff ff ff", target_ip_address)
							
							SendRawPacket(network_interface, packet)
							
	return	
	
def SendRArp(target_mac_address):
	Send(3, target_mac_address, "0.0.0.0")
	return
	
def SendInArp(target_mac_address):
	return
	
