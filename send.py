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

class OperationCode:
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

def CreateArpPacket(sender_mac_address, sender_ip_address, target_ip_address):
		
	#Ethernet Layer
	packet =  bytes.fromhex("ff ff ff ff ff ff")
	packet += bytes.fromhex( sender_mac_address.replace(":", "") )
	packet += Type.Arp

	#Arp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += OperationCode.Request

	#Data
	packet += bytes.fromhex(sender_mac_address.replace(":", ""))
	packet += socket.inet_aton(sender_ip_address)
	packet += bytes.fromhex("ffffffffffff")
	packet += socket.inet_aton(target_ip_address)
	
	return packet
	
def CreateRArpPacket(sender_mac_address, target_mac_address):

	#Ethernet Layer
	packet =  bytes.fromhex("ff ff ff ff ff ff")
	packet += bytes.fromhex( sender_mac_address.replace(":", "") )
	packet += Type.Arp
	
	#Rarp Layer
	packet += HardwareType.Ethernet
	packet += ProtocolType.IPv4
	packet += HardwareSize.MAC
	packet += ProtocolSize.IPv4
	packet += OpcodeRArp.Request
	
	 
	#Data
	packet += bytes.fromhex( sender_mac_address.replace(":", "") )
	packet += socket.inet_aton("0.0.0.0")
	packet += bytes.fromhex(target_mac_address)
	packet += socket.inet_aton("0.0.0.0")
	
	return packet
	
	

def Decode(packet):
	structure = {}
	structure.update( {"oper": packet[20:22]} )
	structure.update( {"sha": packet[22:28]} )
	structure.update( {"spa": packet[28:32]} )
	structure.update( {"tha": packet[32:38]} )
	structure.update( {"tpa": packet[38:42]} )

	return structure

def SendRawPacket(network_interface, packet):
	if network_interface in NetworkInterfaces():
			pass
	else:
			return
	
	sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	sender.bind((network_interface, 0))
	
	sender.send(packet)

def SendArp(target_ip_address):
	if NetworkInterfaces() is None:
			return
	for interface in NetworkInterfaces():
			if InterfaceMacAddresses(interface) is None or interface[0:2] == 'lo':
					continue
			for mac in InterfaceMacAddresses(interface):
					if InterfaceIpAddresses(interface) is None:
							continue
					for ip in InterfaceIpAddresses(interface):
							if ip is None:
									continue
							packet = CreateArpPacket(mac, ip, target_ip_address)
							SendRawPacket(interface, packet)
	return
	
def SendRArp(target_mac_address):
	if NetworkInterfaces() is None:
			return
	for interface in NetworkInterfaces():
			if InterfaceMacAddresses(interface) is None or interface[0:2] == 'lo':
					continue
			for mac in InterfaceMacAddresses(interface):
					if InterfaceIpAddresses(interface) is None:
							continue
					for ip in InterfaceIpAddresses(interface):
							if ip is None:
									continue
							packet = CreateRArpPacket(mac, target_mac_address)
							
							SendRawPacket(interface, packet)
	return