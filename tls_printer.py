#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from nfstream import NFStreamer
import os.path
import sys

############################################################################
#               python3 tls_printer.py <pcap_file>
############################################################################

#file containing top 1000 most visited sites
FILENAME="top10k.txt"

def print_flows(flows,total_packets):
    if flows is None:
        return
    pkt_count = get_pkt_count(flows)
    if pkt_count>0 and flows[0].application_name != "":
        print(str(pkt_count) + "("+ str(round((pkt_count*100)/total_packets,2))+"%)"+ " packets are " + flows[0].application_name.split('.')[0])
        for i in range(0,len(flows)):
            perc=round((flows[i].bidirectional_packets*100)/pkt_count,2)
            print("                   "+ str(i) +") "+ flows[i].application_name + "  --  "+flows[i].src_ip+"  --  "+flows[i].dst_ip+ "  --  "+flows[i].requested_server_name+ " ("+str(perc)+"%)" )


def detect_tls_traffic(flows):
    if flows is None:
        return
    for i in range(0,len(flows)):
        #retrieve informations about flows[i] 
        server_name_raw=flows[i].requested_server_name
        l=server_name_raw.split('.')
        if(len(l)>1):
            server_name=l[-2]
        else:
            server_name=server_name_raw
        if "." not in flows[i].application_name:
            if grep(server_name):
                flows[i].application_name="TLS."+server_name
            else :
                flows[i].application_name="TLS.Unknown"

def grep(s_name):
    # boolean for grep s_name $FILENAME
    if(s_name == ""):
        return False
    with open(FILENAME) as f :
        for line in f:
            if s_name in line:
                f.close()
                return True
        f.close()
        return False

def get_pkt_count(flows):
    x = 0
    for i in range(0,len(flows)):
        x += flows[i].bidirectional_packets
    return x

def split_by_app_name(tls_flows):
    #split a flow list into two flow lists: one with the flows with traffic that has been recognized from nDPI(e.g TLS.Facebook), and the other with the flows that hasn't been recognized 
    known=[]
    unknown=[]
    for i in range(0,len(tls_flows)):
        if "." in tls_flows[i].application_name:
            known.append(tls_flows[i])
        else :
            unknown.append(tls_flows[i])
    return known,unknown

def sort_(flows):
    #sort a list of flows ; put the TLS.Unknown traffic at the end
    tls_unknown=[]
    tls_known=[]
    for i in range(0,len(flows)):
        if "TLS.Unknown" in flows[i].application_name:
            tls_unknown.append(flows[i])
        else :
            tls_known.append(flows[i])
    sorted_flows=tls_known + tls_unknown
    return sorted_flows

#used to sort a flow list by application_name
def myfunc(e):
    return e.application_name

if __name__ == "__main__":
    path = sys.argv[1]
    if ".pcap" not in path:
        print(path + " not a .pcap file, exiting")
        sys.exit()
    if not os.path.isfile(FILENAME):
        print(FILENAME+" not found, exiting")
        sys.exit()
    flow_streamer = NFStreamer(source=path, statistical_analysis=True)
    result = {}
    tls_flows = []
    http_flows = []
    total_packets = 0
    i = 0
    try:
        for flow in flow_streamer:
            i = i + 1
            if("TLS" in flow.application_name):
                tls_flows.append(flow)
            elif("HTTP" in flow.application_name):
                #
                http_flows.append(flow)
            try:
                result[flow.application_name] += flow.bidirectional_packets
                total_packets += flow.bidirectional_packets
            except KeyError:
                result[flow.application_name] = flow.bidirectional_packets
                total_packets += flow.bidirectional_packets
        print("Summary (Application Name: Packets):")
        print(result)
        print(str(total_packets) + " total packets")
        #
        tls_known , tls_unknown = split_by_app_name(tls_flows)
        detect_tls_traffic(tls_unknown)
        tls_flows = tls_known + tls_unknown
        tls_flows.sort(key=myfunc)
        sorted_flows=sort_(tls_flows)
        #need to merge 'TLS.Unknown' traffic


        #
        print_flows(sorted_flows,total_packets)
        #print_flows(http_flows,total_packets)

    except KeyboardInterrupt:
        print("Summary (Application Name: Packets):")
        print(result)
        print_flows(tls_flows)
#        print_flows(http_flows)
        print("Terminated.")

