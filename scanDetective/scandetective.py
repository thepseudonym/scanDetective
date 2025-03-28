# Coded by: thepseudonym

import scapy.all as scapy
import argparse

detective = r"""
		 _______________________ 
                <           ...         >
                 ----------------------- 
                              \  
                               \
                             /^\/^\
                             \----|
                         _---'---~~~~-_
                          ~~~|~~L~|~~~~
                             (/_  /~~--
                           \~ \  /  /~
                         __~\  ~ /   ~~----,
                         \    | |       /  \
                         /|   |/       |    |
                         | | | o  o     /~   |
                       _-~_  |        ||  \  /
                      (// )) | o  o    \\---'
                      //_- |  |          \
                     //   |____|\______\__\
                     ~      |   / |    |
                             |_ /   \ _|
                           /~___|  /____\
"""
print(detective)

def getArguments():
    target = input("[1] Type IP / IP range: ")
    return target


def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast/arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose = False)[0]
   
    clientsList = []
    for element in answeredList:
        clientsDict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clientsList.append(clientsDict)
    return clientsList

def printResults(resultsList):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in resultsList:
        print(client["ip"] + "\t\t" + client["mac"])

scanResults = scan(getArguments())
printResults(scanResults)
