#importing modules
import scapy.all as scapy
import argparse


#function for parsing
def parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / Range of IP")
    option1 = parser.parse_args()
    return option1


#function for scanning
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    clients_list = []
    for element in answered_list:
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dictionary)
    return clients_list


#function for printing
def print_result(result_list):
    print("IP\t\t\tMAC Address\n.........................................................")
    for client in result_list:
        print(client["ip"] +"\t\t"+ client["mac"])


option1 = parsing()
scan_result = scan(option1.target)
print_result(scan_result)

