#!/usr/bin/env python
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP or range of IP addresses to scan for")
    (options, arguments) = parser.parse_args()
    # if not options.ip:
    #   parser.error("[-] Please specify an IP or a range of IP addresses. Use --help for more information")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        # print(f"{element[1].psrc}\t|\t{element[1].hwsrc}")
        clients_list.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    # print(clients_list)
    return clients_list


def print_result(results_list):
    print("IP\t\t|\tMAC ADDRESS\n--------------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
if options:
    scan_result = scan(options.target)
    print_result(scan_result)
