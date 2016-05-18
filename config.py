#!/usr/bin/python3

import io
import csv
import sys
import argparse	

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", dest="mac", type=str, help="MAC address")
	parser.add_argument("-i", dest="ip", type=str, help="IP address")
	
	parser.add_argument("-l", dest="list", action="store_true", help="list RARP table")
	parser.set_defaults(list=False)
	
	results = parser.parse_args()
	
	if results.list == True:
		with open("rarp_server.csv", "r") as config_file:
			data = list(csv.reader(config_file))
			
			print()
			print("=========================================")
			print("{0:<20} {1:<20}".format("MAC", "IP"))
			print()
			for row in data:
				print("{0:<20} {1:<20}".format(row[0], row[1]))
			
			print("=========================================")
			print()
	else:
		data = None
		with open("rarp_server.csv", "r") as config_file:
			data = list(csv.reader(config_file))
			
		mac = results.mac
		ip  = results.ip
		
		found = False
		for row in data:
			if row[0] == mac:
				found  = True
				row[1] = ip
		
		if found == False:
			data.append([mac,ip])
			
		
		with open("rarp_server.csv", "w") as config_file:
			writer = csv.writer(config_file)
			
			for row in data:
				writer.writerow(row)
	
	return


if __name__ == '__main__':
	main()