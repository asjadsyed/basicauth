#!/usr/bin/env python3

import base64
import logging
import re
import sys
import time
from typing import List
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

DEFAULT_BPF_FILTER: str = "tcp port 80"
BASIC_AUTH_FILTER: re.Pattern = re.compile(rb"Authorization: Basic (.*)")
HOST_FILTER: re.Pattern = re.compile(rb"Host: (.*)")
VALID_METHODS: List[bytes] = [b"OPTIONS", b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"TRACE", b"CONNECT"]
METHOD_FILTER: re.Pattern = re.compile(b"(" + b"|".join(VALID_METHODS) + b") (.*) HTTP.*?")


def format_password(packet):
	if Raw not in packet:
		return
	raw = packet[Raw].load
	contains_basic_auth = BASIC_AUTH_FILTER.search(raw)
	if contains_basic_auth:
		result = ""
		result += time.ctime() + " | "
		client = ""
		try:
			client = f"{packet[IP].src}:{packet[TCP].sport}"
		except IndexError:
			client = "ClientParseError"
		result += client + " -> "
		server = ""
		try:
			server = f"{packet[IP].dst}:{packet[TCP].dport}"
		except IndexError:
			server = "ServerParseError"
		result += server + " | "
		contains_method = METHOD_FILTER.search(bytes(packet))
		method = ""
		method_with_spacing = ""
		if contains_method:
			method = contains_method.group(1).strip().decode()
			method_with_spacing = f"{method} "
			result += method_with_spacing
		url = ""
		contains_host = HOST_FILTER.search(bytes(packet))
		if contains_host:
			host = contains_host.group(1).rstrip().decode()
			url += f"http://{host}"
		if contains_method:
			requested_file_path = contains_method.group(2).strip().decode()
			url += requested_file_path
		result += url
		result += " | ["
		creds = contains_basic_auth.group(1).strip().decode()
		result += f"{creds}"
		plain = ""
		try:
			plain = base64.b64decode(creds).decode()
		except TypeError:
			plain = "DecodingError"
		result += f"] [{plain}]"
		return result

def check_for_password(packet) -> bool:
    if Raw not in packet:
        return False
    return BASIC_AUTH_FILTER.search(packet[Raw].load) is not None

def print_usage(argv):
	whitespace_for_indent = " " * len(argv[0])
	print("usage:   \t" + argv[0] + " [OPTION] [...]")
	print("         \t" + argv[0] + " -r <capture file> [OPTION] [...]")
	print("         \t" + argv[0] + " -h")
	print("options: \t" + whitespace_for_indent + " -i           <interface>")
	print("         \t" + whitespace_for_indent + " --interface  <interface>")
	print("         \t" + whitespace_for_indent + " -c           <count>")
	print("         \t" + whitespace_for_indent + " --count      <count>")
	print("         \t" + whitespace_for_indent + " -t           <total time>")
	print("         \t" + whitespace_for_indent + " --time       <total time>")
	print("         \t" + whitespace_for_indent + " -bpf         <berkeley packet filter>")
	print("         \t" + whitespace_for_indent + " --bpf        <berkeley packet filter>")
	print("         \t" + whitespace_for_indent + " --berkeley   <berkeley packet filter>")
	print("         \t" + whitespace_for_indent + " --berkeleypf <berkeley packet filter>")
	print("         \t" + whitespace_for_indent + " -w           <dump file>")
	print("         \t" + whitespace_for_indent + " --write      <dump file>")
	print("         \t" + whitespace_for_indent + " -W           open in Wireshark")
	print("         \t" + whitespace_for_indent + " --wireshark  open in Wireshark")
	print("         \t" + whitespace_for_indent + " --Wireshark  open in Wireshark")
	print("         \t" + whitespace_for_indent + " -q           don't format or print found credentials")
	print("         \t" + whitespace_for_indent + " --quiet      don't format or print found credentials")
	print("examples:\t" + argv[0] + " -i eth0")
	print("     \t\t\t Sniff on interface eth0")
	print("         \t" + argv[0] + " -r capture.pcap")
	print("     \t\t\t Read from file capture.pcap")
	print("         \t" + argv[0] + " -c 100 -i wlan0 -w creds.pcap")
	print("     \t\t\t Sniff 100 logins on interface wlan0")
	print("     \t\t\t Save the relevant packets to the file creds.pcap")
	print("         \t" + argv[0] + " -W")
	print("     \t\t\t Sniff on all interfaces")
	print("     \t\t\t Then open the relevant packets in Wireshark")
	print("     \t\t\t Press Control-C in console to stop capture")
	print("         \t" + argv[0] + " -i tap0 -t 60 -bpf \"tcp port 8080\"")
	print("     \t\t\t Capture on tap0 for one minute, filtering for logins only on port 8080")
	print("         \t" + argv[0] + " -c 1 -i eth1 -t 600")
	print("     \t\t\t Sniff for one login on interface eth1, for up to ten minutes, whichever comes first")

def print_header():
	print("Time and Date | ClientIP:Port -> ServerIP:Port | METHOD http://host/path/file | [encodedcredentials] [decodedusername:andpassword]")

def main(argv):
	open_in_wireshark = False
	dump_file = None
	if "-h" in argv or "--help" in argv:
		print_usage(argv)
		exit()

	sniff_args = {"prn": format_password, "store": 0, "filter": DEFAULT_BPF_FILTER, "lfilter": check_for_password}
													# time to handle options without arguments
	if "-q" in argv or "--quiet" in argv:
		sniff_args["prn"] = None							# unset print function
		argv = [arg for arg in argv if arg != "-q" and arg != "--quiet"]			# remove all quiet options now
	if "-W" in argv or "--wireshark" in argv or "--Wireshark" in argv:
		open_in_wireshark = True							# set value to check later for deciding whether or not to open wireshark
		sniff_args["store"] = 1								# re-enable store, by default is off, and is needed to open in wireshark
		argv = [arg for arg in argv if arg != "-W" and arg != "--wireshark" and arg != "--Wireshark"]			# remove all wireshark options now
													# time to handle options with arguments
	if len(argv) % 2 == 1:									# we should have an odd amount of arguments after removing quiet and wireshark options (because each option should have a value after it)
		for arg_index in range(1, len(argv), 2): 				# start on the first argument up until the last, skipping every second argument
			if argv[arg_index] in ["-i", "--interface"]:			# interface
				sniff_args["iface"] = argv[arg_index + 1]
			elif argv[arg_index] in ["-r", "--read"]:				# file to read from
				sniff_args["offline"] = argv[arg_index + 1]
			elif argv[arg_index] in ["-c", "--count"]:				# count
				sniff_args["count"] = int(argv[arg_index + 1])
			elif argv[arg_index] in ["-t", "--time"]:				# time
				sniff_args["timeout"] = float(argv[arg_index + 1])
			elif argv[arg_index] in ["-bpf", "--bpf", "--berkeley", "--berkeleypf"]:		# berkeley packet filter
				sniff_args["filter"] = sys.argv[arg_index + 1]
			elif argv[arg_index] in ["-w", "--write"]:							# write to file
				sniff_args["store"] = 1									# re-enable store, by default is off
				dump_file = argv[arg_index + 1]							# set file to dump packets to
			else:
				print_usage(argv)
				exit()
		print_header()
		saved_packets = sniff(**sniff_args)
		if saved_packets:											# if we actually captured any packets
			if dump_file:												# and if we set a dump file
				wrpcap(dump_file, saved_packets)							# write them
			if open_in_wireshark:										# also if we want to open in wireshark
				wireshark(saved_packets)									# do it
	else:													# if we don't have an odd amount of arguments, they didn't enter valid arguments
		print_usage(argv)
		exit()

if __name__ == "__main__":
	main(sys.argv)
