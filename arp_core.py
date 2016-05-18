import socket
import netifaces as ni
import struct
import binascii



# Enumerate
#
#
#
class Type:
	Arp  = bytes.fromhex("0806")
	RArp = bytes.fromhex("0806")
	RArp2 = bytes.fromhex("8035")

class HardwareType:
	Ethernet   = bytes.fromhex("0001")
	FrameRelay = bytes.fromhex("000f")

class ProtocolType:
	IPv4 = bytes.fromhex("0800")

class HardwareSize:
	MAC = bytes.fromhex("06")

class ProtocolSize:
	IPv4        = bytes.fromhex("04")
	IPv6        = bytes.fromhex("06")
	Q922_2bytes = bytes.fromhex("02")
	Q922_3bytes = bytes.fromhex("03")
	Q922_4bytes = bytes.fromhex("04")

class Opcode:
	ArpRequest   = bytes.fromhex("0001")
	ArpReply     = bytes.fromhex("0002")
	RArpRequest  = bytes.fromhex("0003")
	RArpReply    = bytes.fromhex("0004")
	InArpRequest = bytes.fromhex("0008")
	InArpReply   = bytes.fromhex("0009")



# Interface Informations
#
#
#
def Interfaces():
	return ni.interfaces()


def InterfaceMacAddresses(network_interface):
	mac_addresses = []
	try:
		for mac_info in ni.ifaddresses(network_interface)[ni.AF_PACKET]:
			mac_addresses.append(mac_info['addr'])
	except:
		pass
	return mac_addresses

def InterfaceQ922Address(network_interface):
	
	return []

def InterfaceIpv4Addresses(network_interface):
	ip_addresses = []
	try:
		for ip_info in ni.ifaddresses(network_interface)[ni.AF_INET]:
			ip_addresses.append(ip_info['addr'])
	
	except:
		pass
	
	return ip_addresses


def InterfaceIpv6Addresses(network_interface):
	ip_addresses = []
	try:
		for ip_info in ni.ifaddresses(network_interface)[ni.AF_INET6]:
			ip_addresses.append(ip_info['addr'])
			
	except:
		pass
	
	return ip_addresses


# Packet Format
#
#
#
#

# ARP
def CreateArpRequestPacket(sender_mac_address, sender_proto_address, target_mac_address, target_proto_address):
	
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
	packet += socket.inet_aton(sender_proto_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_proto_address)
	
	return packet

def CreateArpReplyPacket(sender_mac_address, sender_proto_address, target_mac_address, target_proto_address):
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
	packet += socket.inet_aton(sender_proto_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_proto_address)
	
	return packet



# RARP
def CreateRArpRequestPacket(sender_mac_address, sender_proto_address, target_mac_address, target_proto_address):
	
	# Ethernet Layer
	packet  = bytes.fromhex("ff ff ff ff ff ff")
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.RArp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.RArpRequest
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_proto_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_proto_address)
	
	return packet

def CreateRArpReplyPacket(sender_mac_address, sender_proto_address, target_mac_address, target_proto_address):

	# Ethernet Layer
	packet = bytes.fromhex(target_mac_address.replace(":", " "))
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += Type.RArp
	
	# Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += Opcode.RArpReply
	
	packet += bytes.fromhex(sender_mac_address.replace(":", " "))
	packet += socket.inet_aton(sender_proto_address)
	packet += bytes.fromhex(target_mac_address.replace(":", " "))
	packet += socket.inet_aton(target_proto_address)
	
	return packet


# Socket
#
#
#
#
def SendRawPacket(network_interface, packet):
	if network_interface in Interfaces():
			pass
	else:
			return
	
	sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	sender.bind((network_interface, 0))
	
	sender.send(packet)



# Send ARP packet
#
#
#
#
def SendArpRequestPacket(target_ip_address = None):

	# Network interface
	#
	#
	#
	network_interfaces = Interfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Ignore 'lo'
			#
			#
			if network_interface == 'lo':
				continue
			
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_addresses is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_ip_addresses = InterfaceIpv4Addresses(network_interface)
					
					if interface_ip_addresses is not None:
						for interface_ip_address in interface_ip_addresses:
							
							# Send ARP Packet
							#
							#
							#
							packet = CreateArpRequestPacket(interface_mac_address, interface_ip_address, "ff ff ff ff ff ff", target_ip_address)
							
							SendRawPacket(network_interface, packet)
							
	return
	
	
# Send ARP reply 
#
#
#
#
def SendArpReplyPacket(sender_ip_address, target_mac_address, target_ip_address):
	# Network interface
	#
	#
	#
	network_interfaces = Interfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Ignore 'lo'
			#
			#
			if network_interface == 'lo':
				continue
			
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_addresses is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_ip_addresses = InterfaceIpv4Addresses(network_interface)
					
					if sender_ip_address in interface_ip_addresses:
					
						# Send ARP Packet
						#
						#
						#
						packet = CreateArpReplyPacket(interface_mac_address, sender_ip_address, target_mac_address, target_ip_address)
						
						SendRawPacket(network_interface, packet)
	
	return
	
	
# Send RARP packet
#
#
#
#
def SendRArpRequestPacket():

	# Network interface
	#
	#
	#
	network_interfaces = Interfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Ignore 'lo'
			#
			#
			if network_interface == 'lo':
				continue
				
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_addresses is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_ip_addresses = InterfaceIpv4Addresses(network_interface)
					
					if interface_ip_addresses is not None:
						for interface_ip_address in interface_ip_addresses:
							
							# Send RARP request packet
							#
							#
							#
							packet = CreateRArpRequestPacket(interface_mac_address, "0.0.0.0", "ff:ff:ff:ff:ff:ff", "0.0.0.0")
							
							SendRawPacket(network_interface, packet)
							
	
	return
	
def SendRArpReplyPacket(target_mac_address, target_ip_address):
	# Network interface
	#
	#
	#
	network_interfaces = Interfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Ignore 'lo'
			#
			#
			if network_interface == 'lo':
				continue
			
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_addresses is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_ip_addresses = InterfaceIpv4Addresses(network_interface)
					
					if interface_ip_addresses is not None:
						for interface_ip_address in interface_ip_addresses:
							
							# Send ARP Packet
							#
							#
							#
							packet = CreateRArpReplyPacket(interface_mac_address, interface_ip_address, target_mac_address, target_ip_address)
							
							SendRawPacket(network_interface, packet)

# Send InARP packet
#
#
#
#
def SendInArpRequestPacket():

	# Network interface
	#
	#
	#
	network_interfaces = Interfaces()
	
	if network_interfaces is not None:
		for network_interface in network_interfaces:
			
			# Ignore 'lo'
			#
			#
			if network_interface == 'lo':
				continue
				
			# Interface MAC Address
			#
			#
			#
			interface_mac_addresses = InterfaceMacAddresses(network_interface)
			
			if interface_mac_addresses is not None:
				for interface_mac_address in interface_mac_addresses:
					
					# Interface IP Address
					#
					#
					#
					interface_Q922_addresses = InterfaceQ922Addresses(network_interface)
					
					if interface_ip_addresses is not None:
						for interface_ip_address in interface_ip_addresses:
							
							# Send RARP request packet
							#
							#
							#
							packet = CreateInArpRequestPacket()
							
							SendRawPacket(network_interface, packet)
							
	return
