#!/usr/bin/python3

import argparse
import arp_core
	
if __name__ == "__main__":
	
	parser = argparse.ArgumentParser()
	
	parser.add_argument("-a", dest="ip", help="target ip address")
	
	args = parser.parse_args()
	arp_core.SendArpRequestPacket(args.ip)