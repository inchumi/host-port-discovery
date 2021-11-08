#!/usr/bin/python3

import sys
import netifaces
import os
import platform
import nmap3
import requests
import json

lenargs = len(sys.argv)
oper = platform.system()
ifacesArray = netifaces.interfaces() ## List all interfaces detected
nmap = nmap3.Nmap()

## Prepare variables to export
json_result = {}
url = "http://127.0.0.1/example/fake_url.php"

## Check for arguments
if (lenargs == 3 and sys.argv[1] == "-i"):
	selectedIface = sys.argv[2]
	## Check network. Where we are?
	try:
		ifacesArray.index(selectedIface)
		CIDR_Network = os.popen("ip a | grep " + selectedIface + " | awk 'NR==2{print $2}' | tr -d '\n'").readlines()
	except:
		print ("\nUps!. That interface doesn't exist!\n")
		print ("Options:")
		print ("-------")
		for i in ifacesArray:
			print ( "\tpython3 " + str(sys.argv[0]) + " -i " + i)
		print ("\n")
		sys.exit(1)

	print ("\nWelcome to DAVISCOVERY!\n")
	print ("  ...Searching for live hosts on: " + str(selectedIface) + "\t(" + CIDR_Network[0] + ")")
	print ("\n\n==============================================================\n\n\n")

	hostsUP = os.popen("nmap -n -sn -PE -T4 --open --packet-trace " + CIDR_Network[0] + " 2>/dev/null | grep 'Nmap scan report' | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'")
	hosts = []
	for ip in hostsUP:
		hosts.append(ip.strip())
	print (str(len(hosts)) + " active hosts was found!\n\n")

	if (oper == "Windows"):
	   ping = "ping -n 1 "
	elif (oper == "Linux"):
	   ping = "ping -c 1 "
	else :
	   ping = "ping -c 1 "

	for hostup in hosts:
		addr = hostup
		comm = ping + addr
		response = os.popen(comm)
		for line in response.readlines():
			# Checking SO quickly by TTL (just Windows/Linux for now)
			if (line.count("ttl")):
				SO = "LINUX/UNIX" if line.count("ttl=64") else "WINDOWS"
				results = nmap.scan_top_ports(addr, args="--script banner -Pn -n --min-rate 5000 -T5 --top-ports 1000")

				#Try to find hostname
				hostname = "hostname not found"
				try:
					hostname = str(results[addr]["hostname"][0]["name"])
				except:
					print ("IP: " + addr, "\t[" + hostname + "]\t" , " (" + SO + ")\n\n")
				#Try to extract ports info
				tcp_detected_ports = []
				udp_detected_ports = []
				try:
					for i in results[addr]["ports"]:
						if (i["state"] == "open"):
							## Saving results on json_result variable
							newkey = str(addr)
							json_result[newkey] = results[addr]

							## Getting banner info data if exist
							bannerInfo = ""
							try:
								banner_info = str(i["scripts"][0]["raw"])
							except:
								banner_info = ""

							if (i["protocol"] == "tcp"):
								tcp_detected_ports.append(i["portid"] + ":" + i["service"]["name"] + "\t" + banner_info)
							elif (i["protocol"] == "udp" ):
								udp_deteted_ports.append(i["portid"] + ":" + i["service"]["name"] + "\t" + banner_info)

					## Print data to user
					print ("\n\tProtocol TCP:")
					print ("\t-------------")						
					if (len(tcp_detected_ports) > 0):
						for port in tcp_detected_ports:
							print ("\t\t\t" + port)
					else:
						print ("\n\t\t\tNo open TCP ports here :( \n")

					print (" \n\tProtocol UDP:")
					print ("\t-------------")						
					if (len(udp_detected_ports) > 0):
						for port in udp_detected_ports:
							print ("\t\t\t" + port)
					else:
						print ("\n\t\t\tNo open UDP ports here :( \n")

				except Exception as ex:
					print ("\n\t\tThis host appears to have no exposed ports (?)\n")
					print (ex)
				print ("\n\n==============================================================\n")

	## Sending data to predefined endopint
	try:
		response = requests.post(url, json_result)
		post_data = "Sending data to " + url + "...[OK]"
	except:
		post_data = "Sending data to " + url + "...[ERROR]"
	print ("[*] " + post_data)

	## Save data to output.json
	try:
		with open("output.json", "a") as outfile:
			json.dump(json_result, outfile)
		export_data = "Exporting results to ./output.json...[OK]"
	except:
		export_data = "Exporting results to ./output.json...[ERROR]"
	print ("[*] " + export_data)

else:
	print ("\n[*] usage: " + str(sys.argv[0]) + " -i <interface>")
	print ("\nOptions:")
	print ("-------")
	for i in ifacesArray:
		print ( "\tpython3 " + str(sys.argv[0]) + " -i " + i)
	print ("\n")
	sys.exit(1)
print ("\n")
