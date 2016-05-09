import dpkt
import sys
import socket
import collections

DEBUG = False

def conn_id_to_str(cid):
  '''
  cid = (srcip, sport, dstip, dport)
  :param cid:
  :return:
  '''
  return cid[0] + ':' + str(cid[1]) + "<=>" + cid[2] + ':' + cid[3]


def UDP_info(buf):
  pass


def main(filename, debug_info=True):
    '''
       Parse pcap file and get DNS, TCP packets info
    '''
    
    TCP_FHS = 1
    TCP_SHS = 2
    TCP_THS = 3
    
    my_src_ip = ""

    tcp_conn_state = {}
    pkt_counter = 0

    dns_total_time = 0

    dns_sites_counter = 0

    dns_query_counter = 0
    dns_response_counter = 0
    object_req_counter = 0

    events_table = collections.OrderedDict()
    
    dst_ip_set = set()

    for ts, buf in dpkt.pcap.Reader(open(filename,'r')):
        pkt_counter += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        elif eth.type != dpkt.ethernet.ETH_TYPE_IP6:
            pass

        ip = eth.data

        srcip = socket.inet_ntoa(ip.src)
        dstip = socket.inet_ntoa(ip.dst)

        if ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            # This is an DNS query.
            if udp.sport != 53 and udp.dport != 53:
                continue
            dns = dpkt.dns.DNS(udp.data)
            if dns.qr == dpkt.dns.DNS_Q:
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    if debug_info:
                        print "A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode
                    continue

                if dns.qd[0].type != dpkt.dns.DNS_A:
                    continue

                if dns.qd[0].cls != dpkt.dns.DNS_IN:
                    continue

                if my_src_ip == "":
                    if debug_info:
                        print "*******************"
                        print "SRC IP IS SET: ", socket.inet_ntoa(ip.src)
                        print "*******************"
                    my_src_ip = socket.inet_ntoa(ip.src)

                if DEBUG:
                    print "query for ", dns.qd[0].name, "ID is ", dns.id, "dns.qr is ", dns.qr, "query type is ", dns.qd[0].type
                    print "dns.qd is ", dns.qd

                if debug_info:
                    print dns.id, "DNS query name:", dns.qd[0].name

                events_table["DNS_" + str(dns.id)] = {"start_time":ts,
                                              "end_time":0,
                                              "src":srcip,
                                              "dst":dstip,
                                              "bytes_involved":ip.len,
                                              "packets_involved":1,
                                              "rtt_num":0,
                                              "packets_loss":0
                                              }
                dns_query_counter += 1
                
            else:
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    print "Error: no DNS_QUERY, opcode: ", dns.opcode
                    continue

                if dns.qr != dpkt.dns.DNS_R :
                    print "A DNS packet was received from a name server, but dns.qr is not 1 and should be.  It is %d" % dns.qr
                    continue

                if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
                    continue

                if len(dns.an) < 1:
                    continue

                dns_response_counter += 1
                for res in dns.an:
                    if res.type == dpkt.dns.DNS_CNAME:
                        if debug_info:
                            print dns.id, "CNAME ", res.name, "\tGot response from", res.cname

                    elif res.type == dpkt.dns.DNS_A:
                        ip_tag = socket.inet_ntoa(res.rdata)
                        dst_ip_set.add(ip_tag)
                        dns_sites_counter += 1
                        if debug_info:
                            print dns.id, "A ", res.name, "\tGot response from", ip_tag
                    elif res.type == dpkt.dns.DNS_PTR:
                        pass

                event_id = "DNS_" + str(dns.id)

                if event_id not in events_table:
                    continue

                events_table[event_id]["packets_involved"] += 1
                events_table[event_id]["end_time"] = ts
                events_table[event_id]["bytes_involved"] += ip.len

                dns_total_time += events_table[event_id]["end_time"] - events_table[event_id]["start_time"]

        if ip.p == dpkt.ip.IP_PROTO_TCP and my_src_ip != "":
            if srcip not in dst_ip_set and dstip not in dst_ip_set:
                if debug_info:
                    print "Unknown src or dst ip address."
                continue

            tcp = ip.data
            if my_src_ip == srcip:
                conn_header = srcip + ':' + str(tcp.sport) + '-' + dstip + ':' + str(tcp.dport)
            else:
                conn_header = dstip + ':' + str(tcp.dport) + '-' + srcip + ':' + str(tcp.sport)

            # TCP_FLAG_KEY: http://rapid.web.unc.edu/resources/tcp-flag-key/
            fin_flag = ( tcp.flags & 0x01 ) != 0
            syn_flag = ( tcp.flags & 0x02 ) != 0
            rst_flag = ( tcp.flags & 0x04 ) != 0
            psh_flag = ( tcp.flags & 0x08 ) != 0
            ack_flag = ( tcp.flags & 0x10 ) != 0
            urg_flag = ( tcp.flags & 0x20 ) != 0
            ece_flag = ( tcp.flags & 0x40 ) != 0
            cwr_flag = ( tcp.flags & 0x80 ) != 0
            flags = (
                      ( "C" if cwr_flag else " " ) +
                      ( "E" if ece_flag else " " ) +
                      ( "U" if urg_flag else " " ) +
                      ( "A" if ack_flag else " " ) +
                      ( "P" if psh_flag else " " ) +
                      ( "R" if rst_flag else " " ) +
                      ( "S" if syn_flag else " " ) +
                      ( "F" if fin_flag else " " ) )

            if fin_flag:
                print "TCP packet finished."
                continue

            # First TCP handshake.
            if conn_header not in tcp_conn_state:
                if tcp.flags & dpkt.tcp.TH_SYN and not tcp.ack:
                    if debug_info:
                        print "new TCP connection: %s" % conn_header
                    event_id = "TcpConn_" + conn_header

                    events_table[event_id] = {"start_time":ts,
                                              "end_time":0,
                                              "src":srcip,
                                              "dst":dstip,
                                              "bytes_involved":ip.len,
                                              "packets_involved":1,
                                              "rtt_num":0,
                                              "packets_loss":0
                                              }


                    tcp_conn_state[conn_header] = {}

                    # WHY WAIT? Needs to clear after ack is received.
                    tcp_conn_state[conn_header]["src_waiting_ack"] = [tcp.seq]
                    tcp_conn_state[conn_header]["src_init_seq"] = tcp.seq
                    tcp_conn_state[conn_header]["status"] = TCP_FHS
                    tcp_conn_state[conn_header]["request_counter"] = 0
                    
                    
                else:
                    if debug_info:
                        print "No record for this TCP connection. Pass"
                    continue

            # second tcp handshake
            elif tcp.flags & dpkt.tcp.TH_SYN and tcp.ack:
                if tcp_conn_state[conn_header]["status"] == TCP_FHS:
                    event_id = "TcpConn_" + conn_header
                    events_table[event_id]["bytes_involved"] += ip.len
                    events_table[event_id]["packets_involved"] += 1
                    events_table[event_id]["rtt_num"] += 1
                    
                    # clear the waiting flag for the first handshake
                    tcp_conn_state[conn_header]["src_waiting_ack"].remove(tcp.ack - 1)
                    tcp_conn_state[conn_header]["dst_waiting_ack"] = [tcp.seq]
                    
                    # Waiting for the 3rd handshake
                    tcp_conn_state[conn_header]["dst_init_seq"] = tcp.seq
                    tcp_conn_state[conn_header]["status"] = TCP_SHS
                    
                else:
                    # second handshake packet loss.
                    if debug_info:
                        print "second handshake packet loss"
                    events_table[event_id]["packets_loss"] += 1

            # simply check ack_flag won't work.
            # elif not syn_flag and ack_flag:
            
            elif tcp_conn_state[conn_header]["status"] == TCP_SHS and \
                 len(tcp.data) == 0:
                
                if debug_info:
                    print ">> New TCP connection is established."
                  
                event_id = "TcpConn_" + conn_header
                events_table[event_id]["end_time"] = ts
                events_table[event_id]["bytes_involved"] += ip.len
                events_table[event_id]["packets_involved"] += 1
                events_table[event_id]["rtt_num"] += 1
                
                if tcp.ack - 1 in tcp_conn_state[conn_header]["dst_waiting_ack"]:
                    tcp_conn_state[conn_header]["dst_waiting_ack"].remove(tcp.ack - 1)
                tcp_conn_state[conn_header]["status"] = TCP_THS


            # object request and response
            elif tcp_conn_state[conn_header]["status"] == TCP_THS:
                # HTTP request
                if tcp.dport == 80:
                    # object request
                    if len(tcp.data) > 0:
                        if tcp.seq + len(tcp.data) not in tcp_conn_state[conn_header]["src_waiting_ack"]:
                            tcp_conn_state[conn_header]["request_counter"] += 1
                            tcp_conn_state[conn_header]["src_waiting_ack"].append(tcp.seq + len(tcp.data))
                            if debug_info:
                                print "** New object request comes."
                            object_req_counter += 1
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])

                            events_table[event_id] = {"start_time":ts,
                                              "end_time":0,
                                              "src":srcip,
                                              "dst":dstip,
                                              "bytes_involved":ip.len,
                                              "packets_involved":1,
                                              "rtt_num":0,
                                              "packets_loss":0
                                              }


                        else:
                            if debug_info:
                                print "Retransmit HTTP request"
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])
                            events_table[event_id]["packets_loss"] += 1

                    else:
                        if tcp.ack in tcp_conn_state[conn_header]["dst_waiting_ack"]:
                            tcp_conn_state[conn_header]["dst_waiting_ack"].remove(tcp.ack)
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])
                            events_table[event_id]["rtt_num"] += 1
                            events_table[event_id]["packets_involved"] += 1
                            events_table[event_id]["bytes_involved"] += ip.len
                            events_table[event_id]["end_time"] = ts
                        elif len(tcp_conn_state[conn_header]["dst_waiting_ack"]) == 0 or \
                             tcp.ack > max(tcp_conn_state[conn_header]["dst_waiting_ack"]):
                            continue
                        else:
                            if debug_info:
                                print "Retransmit HTTP response ACK", tcp.ack
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])

                            events_table[event_id]["packets_involved"] += 1
                            events_table[event_id]["packets_loss"] += 1

                elif tcp.sport == 80:
                    if len(tcp.data) > 0:
                        if tcp.seq + len(tcp.data) not in tcp_conn_state[conn_header]["dst_waiting_ack"]:
                            tcp_conn_state[conn_header]["dst_waiting_ack"].append(tcp.seq + len(tcp.data))
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])

                            events_table[event_id]["bytes_involved"] += ip.len
                            events_table[event_id]["packets_involved"] += 1
                            events_table[event_id]["end_time"] = ts
                            
                        else:
                            if debug_info:
                                print "Retransmit HTTP response"
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])
                            events_table[event_id]["packets_loss"] += 1

                    else:
                        if tcp.ack in tcp_conn_state[conn_header]["src_waiting_ack"]:
                            tcp_conn_state[conn_header]["src_waiting_ack"].remove(tcp.ack)
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])

                            events_table[event_id]["packets_involved"] += 1
                            events_table[event_id]["bytes_involved"] += ip.len
                            events_table[event_id]["rtt_num"] += 1
                            events_table[event_id]["end_time"] = ts
                            
                        elif len(tcp_conn_state[conn_header]["src_waiting_ack"]) == 0 or \
                             tcp.ack > max(tcp_conn_state[conn_header]["src_waiting_ack"]):
                            continue
                            
                        else:
                            if debug_info:
                                print "Retransmit HTTP request ACK", tcp.ack
                            event_id = "Obj_" + conn_header + '_' + \
                                         str(tcp_conn_state[conn_header]["request_counter"])

                            events_table[event_id]["packets_involved"] += 1
                            events_table[event_id]["packets_loss"] += 1

                else:
                    if debug_info:
                        print "ERROR: Counld not resolve this HTTP packet."
                    continue
            else:
                if debug_info:
                    print "ERROR: Could not handle this tcp status."
                continue



    if debug_info:
        print "**************************************************************************"
        print "Total number of packets in the pcap file: ", pkt_counter
        print "Total number of object request is: ", object_req_counter
        print "Average dns request time is: ", dns_total_time/dns_query_counter
        print "Total number of dns sites is: ", dns_sites_counter
        print "Total number of dns response is: ", dns_response_counter
        print "**************************************************************************"

    return events_table

if __name__ == "__main__":


    #f = open(sys.argv[1])

    # pcap_file = '../pcaps/verizon_firefox/verizon_firefox_amazon.com_1329845890.47.pcap'
    # pcap_file = '../pcaps/wired_android/wired_android_amazon.com_1329408440.26.pcap'
    # pcap_file = '../pcaps/t-mobile_android/t-mobile_android_amazon.com_1329408864.54.pcap'
    # pcap_file = '../pcaps/t-mobile_firefox/t-mobile_firefox_amazon.com_1329408898.08.pcap'

    pcap_file = '../pcaps/wired_firefox/wired_firefox_amazon.com_1329408462.02.pcap'

    events_table = main(pcap_file)

    sorted_events_table = collections.OrderedDict(sorted(events_table.items(), key=lambda t : t[0]))

    tcp_connections_to_site = {}
    total_bytes = 0
    # for variation of object download
    object_download_info = {}
    object_download_stime = 0
    object_download_etime = 0
    object_start_download_flag = True

    print "Sorted events on key: "
    print "%-50s%-20s%-20s%-20s%-20s%-8s%-5s%-5s" % ("event_id", "srcip", "dstip", "starttime", \
        "endtime", "bytes", "ack", "loss")

    object_bytes = 0
    for event_id, event in sorted_events_table.iteritems():

        print "%-50s%-20s%-20s%-20s%-20s%-8s%-5s%-5s"\
            % (event_id, event["src"], event["dst"], event["start_time"], event["end_time"], event["bytes_involved"],\
            event["rtt_num"], event["packets_loss"])

        if event_id[0:7] == 'TcpConn':
            if event["dst"] not in tcp_connections_to_site:
                tcp_connections_to_site[event["dst"]] = 1
            else:
                tcp_connections_to_site[event["dst"]] += 1



        if event_id[0:3] == 'Obj':
            # calculate object download rate.
            # since it is parallel connection to a site to download object,
            # the rate is calculated by get all bytes requesting from an ip and then
            # divided by the time taken for all connection.

            if event["dst"] not in object_download_info:
                object_bytes = 0
                object_download_info[event["dst"]] = {}
                object_download_info[event["dst"]]["stime"] = event["start_time"]
                object_download_info[event["dst"]]["etime"] = event["end_time"]

            else:
                object_download_info[event["dst"]]["etime"] = event["end_time"]

            object_bytes += event["bytes_involved"]
            object_download_info[event["dst"]]["bytes"] = object_bytes

            if object_start_download_flag:
                object_download_stime = event["start_time"]
                object_start_download_flag = False

            object_download_etime = event["end_time"]
            total_bytes += event["bytes_involved"]


    for ipstr in object_download_info:
        object_download_info[ipstr]["download rate"] = \
            object_download_info[ipstr]["bytes"]/(object_download_info[ipstr]["etime"] - object_download_info[ipstr]["stime"])
    print "Variation in the download rate across objects: ", \
            object_download_info

    print "This is for number of sites and number of TCP connections: "
    print tcp_connections_to_site

    # total_types equals to all object request bytes, time range starting from the first object request,
    # ends with the last request end time.
    print "Average download rate across objects is: ", \
        total_bytes/(1000*(object_download_etime - object_download_stime)), "KB"



