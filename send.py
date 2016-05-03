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

class OpcodeArp:
	Request = bytes.fromhex("0001")
	Reply = bytes.fromhex("0002")
	
class OpcodeRArp:
	Request = bytes.fromhex("0003")
	Reply = bytes.fromhex("0004")
		
class OpcodeInArp:
	Request = bytes.fromhex("0008")
	Reply = bytes.fromhex("0009")
	

class RawSocket:
	def __init__(self):
		self.Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

	def Bind(network_interface):
		self.Socket.bind((network_interface, 0))

	def Send(packet_bytes):
		self.Socket.send(packet_bytes)

	def Receive():
		return self.Socket.recv()

			
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

def InterfaceIpAddresses(network_interface):
	ip_addresses = []
	try:
			for ip_info in ni.ifaddresses(network_interface)[ni.AF_INET]:
					ip_addresses.append(ip_info['addr'])
	except:
			pass
	return ip_addresses

def CreateArpPacket(opcode, sender_mac_address, sender_ip_address, target_mac_address, target_ip_address):
		
	#Ethernet Layer
	if opcode == 1 or opcode == 3:
		packet =  bytes.fromhex("ff ff ff ff ff ff")
	elif opcode == 2 or opcode == 4:
		packet = bytes.fromhex(target_mac_address.replace(":", ""))
		
	packet += bytes.fromhex( sender_mac_address.replace(":", "") )
	packet += Type.Arp

	#Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	
	if opcode == 1:
		packet += OpcodeArp.Request
	elif opcode == 2:
		packet += OpcodeArp.Reply
	elif opcode == 3:
		packet += OpcodeRArp.Request
	elif opcode == 4:
		packet += OpcodeRArp.Reply
	elif opcode == 8:
		packet += OpcodeInArp.Request
	elif opcode == 9:
		packet += OpcodeInArp.Reply

	#Data
	packet += bytes.fromhex(sender_mac_address.replace(":", ""))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex(target_mac_address.replace(":", ""))
	packet += socket.inet_aton(target_ip_address)
	
	return packet

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
	
def SendArp(target_ip_address):
	Send(1, "00:00:00:00:00:00", target_ip_address)
	return
	
def SendRArp(target_mac_address):
	Send(3, target_mac_address, "0.0.0.0")
	return
	
def SendInArp(target_mac_address):
	return