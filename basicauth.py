#!/usr/bin/env python3

from logging import getLogger, ERROR, WARNING
from sys import argv, exit
from re import compile
from base64 import b64decode
from time import ctime
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
conf.verb = 0
getLogger("scapy.runtime").setLevel(WARNING)
dump_file = None
saved_packets = None
open_in_wireshark = False
default_bpf_filter = "tcp port 80"

basic_auth_filter = compile(rb"Authorization: Basic (.*)")
host_filter = compile(rb"Host: (.*)")
valid_methods = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]
valid_methods = [b"OPTIONS", b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"TRACE", b"CONNECT"]
method_filter = compile(b"(" + b"|".join(valid_methods) + b") (.*) HTTP.*?")

def format_password(packet):
	if Raw not in packet:
		return
	raw = packet[Raw].load
	contains_basic_auth = basic_auth_filter.search(raw)
	if contains_basic_auth:
		result = ""
		result += ctime() + " | "
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
		contains_method = method_filter.search(bytes(packet))
		method = ""
		method_with_spacing = ""
		if contains_method:
			method = contains_method.group(1).strip().decode()
			method_with_spacing = f"{method} "
			result += method_with_spacing
		url = ""
		contains_host = host_filter.search(bytes(packet))
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
			plain = b64decode(creds).decode()
		except TypeError:
			plain = "DecodingError"
		result += f"] [{plain}]"
		return result

def check_for_password(packet) -> bool:
    if Raw not in packet:
        return False
    return basic_auth_filter.search(packet[Raw].load) is not None

def print_usage():
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
	print("         \t" + whitespace_for_indent + " -W           means open in Wireshark")
	print("         \t" + whitespace_for_indent + " --wireshark  means open in Wireshark")
	print("         \t" + whitespace_for_indent + " --Wireshark  means open in Wireshark")
	print("         \t" + whitespace_for_indent + " -q           means don't format or print found credentials")
	print("         \t" + whitespace_for_indent + " --quiet      means don't format or print found credentials")
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

if "-h" in argv or "--help" in argv:
	print_usage()
	exit()

sniff_args = {"prn": format_password, "store": 0, "filter": default_bpf_filter, "lfilter": check_for_password}
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
			sniff_args["filter"] = argv[arg_index + 1]
		elif argv[arg_index] in ["-w", "--write"]:							# write to file
			sniff_args["store"] = 1									# re-enable store, by default is off
			dump_file = argv[arg_index + 1]							# set file to dump packets to
		else:
			print_usage()
			exit()
	print_header()
	saved_packets = sniff(**sniff_args)
	if saved_packets:											# if we actually captured any packets
		if dump_file:												# and if we set a dump file
			wrpcap(dump_file, saved_packets)							# write them
		if open_in_wireshark:										# also if we want to open in wireshark
			wireshark(saved_packets)									# do it
else:													# if we don't have an odd amount of arguments, they didn't enter valid arguments
	print_usage()
	exit()

