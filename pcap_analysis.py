# Name Rediet Negash
# 111820799

import dpkt
import sys

# creates an object called flow that has packets sent between the same source and destination
class Flow:
    packets=[]
    sport= dport= ""
    ips = []
    ts = []
    def __init__(P,source,destination):
        P.sport = source
        P.dport = destination
        
#check if it is the requested source and destination ports
def req_source_dest_ports(p1,p2):
    if p1.sport == p2.dport and p2.sport == p1.dport:
        return True
    if p1.sport == p2.sport and p2.dport == p1.dport:
        return True
    return False

#check if it is the requested tcp connection
def req_tcp_flow(p,src_ip,dst_ip):
    if ip_to_str(p.src) == src_ip and ip_to_str(p.dst) == dst_ip:
        return True
    return False

# changes ip network address to string address
def ip_to_str(address):
    return socket.inet_ntoa(address)

# method for calculating throughput
def throughput(flow):
    first_packet = True
    total_payload = first_packet_ts = last_packet_ts = tput = 0
    i=0
    #store the ts when the first packet is sent, there by calculate the total payload by summing each packet's size
    for j in range(0, len(flow.packets)):
       
        if (ip_to_str(flow.ips[j].src) == "130.245.145.12"):
            if first_packet:
                first_packet_ts = flow.ts[j]
                first_packet = False
            else:
                if i<3:
                    if i!=0:
                        print ('Transaction #',i,'  \n\t\tsequence number:- ',flow.packets[j].seq,'\n\t\tack number:- ',flow.packets[j].ack,'\n\t\twindow size:- ',flow.packets[j].win)
                    i += 1
                total_payload += int(len(flow.packets[j]))
                last_packet_ts = flow.ts[j]
    tput = total_payload/(last_packet_ts-first_packet_ts)
    return tput

# method for calculating Loss Rate
def Loss_Rate(flow):
    loss = total_sent = 0
    sequence_dict = {}
    #for each packet, use a dictionary ( key - seq number ) ( value - starts from 1 to so on.... ) value is the number of times a sequence number appeared
    for i in range(0, len(flow.packets)):
        if req_tcp_flow(flow.ips[i],"130.245.145.12","128.208.2.198"):
            total_sent += 1
            sequence_dict[flow.packets[i].seq] = sequence_dict.get(flow.packets[i].seq,0) + 1

    #for each key-value pair in dictionary if a sequence number appears more than once then it means there's a loss
    for key,value in sequence_dict.items():
        if key in sequence_dict:
            loss += sequence_dict[key]-1

    return (loss*1.0/total_sent)

# method for calculating congestion window
def congestion_Window(flow):
    congestion_windows = []
    first_packet = True
    first_packet_ts = last_packet_ts = 0
    seq_number = i = count = c = 0
    for j in range(0, len(flow.packets)):
        c += 1
        if i > 6:
            break
        if req_tcp_flow(flow.ips[j],"130.245.145.12","128.208.2.198"):
            count = count + 1
            if first_packet:
                first_packet_ts = flow.ts[j]
                first_packet = False
                seq_number = int(flow.packets[j].seq)
            elif (flow.ts[j]-first_packet_ts)>(0.073):
                if i!=0:
                    print ("Congestion_Window : %s "%(count*1460),"\n")
                count = 0
                first_packet = True
                i += 1
    print("\n")
# calculate retransmission for triple ack loss and time out 
def Loss_congestion(flow):
    loss = triple_acknowledgement_loss = 0
    sequence_dict = {}
    ack_dict = {}

    for j in range(0, len(flow.packets)):
        if req_tcp_flow(flow.ips[j],"130.245.145.12","128.208.2.198"):
            sequence_dict[flow.packets[j].seq] = sequence_dict.get(flow.packets[j].seq,0) + 1
        
        if req_tcp_flow(flow.ips[j],"128.208.2.198","130.245.145.12"):
            ack_dict[flow.packets[j].ack] = ack_dict.get(flow.packets[j].ack,0) + 1

    for key,value in sequence_dict.items():
        if (key in ack_dict) and (ack_dict[key] > 2):
            triple_acknowledgement_loss += sequence_dict[key]-1
        elif key in sequence_dict:
            loss += sequence_dict[key]-1

    print ("\nTriple Acknowledgement Loss = %s "%str(triple_acknowledgement_loss))
    print ("\nTimeout Loss = %s\n"%str(loss))

    
# main function    
if __name__=='__main__':
    # packets has all tcp packets
    packets = []
    # flows is a list of flow objects that has tcp connections established
    Flows = []
    # has all the ip addresses needed for src and destination checks
    IPs = []
    # has the ts needed for knowing time period for a flow
    timestamps = []
    # counts number of tcp flows or connections found in the pcap file
    tcp_flow_count = 0
    for ts, buf in dpkt.pcap.Reader(open('assignment3.pcap', 'rb')):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                packets.append(tcp)
                IPs.append(ip)
                timestamps.append(ts)
                if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
                # if both AcK and SYC are recieved a new tcp flow/flow is added
                # so create a flow with src and dst port
                    tcp_flow_count += 1
                    flow = Flow(tcp.sport, tcp.dport)
                    flow.packets = []
                    flow.ips = []
                    flow.ts = []
                    Flows.append(flow)
    # add all the connections found to the flow object datafileds and add them to the flows array
    for i in range(len(packets)):
        for flow in range(0,len(Flows),1):
            if req_source_dest_ports(packets[i],Flows[flow]):
                Flows[flow].packets.append(packets[i])
                Flows[flow].ips.append(IPs[i])
                Flows[flow].ts.append(timestamps[i])
                
    # The f/f code is used for printing all the tcp counts, throughputs, Loss Rates, congestion windows and Loss congestions
    k=1
    print ("\nNumber of Tcp flows initiated from the sender = %s \n"%tcp_flow_count)
    for flow in Flows:
        print ("\nFlow #%s" %k)
        print ("***--------------------------------------------------------------***")
        print ("\nFirst two transactions after establishing TCP connection")
        print ("\nThroughput = %s MegaBit/second" %(throughput(flow)/125000))
        print ("\nLoss Rate = %s"%Loss_Rate(flow))
        
        Loss_congestion(flow)
        print("The first 5 congestion window sizes\n")
        congestion_Window(flow)
        
        k += 1


