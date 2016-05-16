class RawSocket:
	def __init__(self):
		self.Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

	def Bind(network_interface):
		self.Socket.bind((network_interface, 0))

	def Send(packet_bytes):
		self.Socket.send(packet_bytes)

	def Receive():
		return self.Socket.recv()