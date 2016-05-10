#!/usr/bin/python3

import sys
import arp_core as arp
	
if __name__ == "__main__":
	
	for arg in sys.argv:
		if arg[0:2] == "-a":
			arp.SendArpRequestPacket(arg[2:])