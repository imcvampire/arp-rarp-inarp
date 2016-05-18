#!/usr/bin/python3

import io
import csv
import sys
import argparse	

def main():
	
	with open("rarp_server.py", "rb") as config_file:
		
		data = list(csv.reader(config_file))
		
	
	return


if __name__ == '__main__':
	main()