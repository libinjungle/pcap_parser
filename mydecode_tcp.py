import dpkt
import sys
import socket
import collections

def UDP_info(buf):



def main(file):
  f = open(file)
  pcap = dpkt.pcap.Reader(f)

  my_src_ip = ""

  pkts_counter = 0
  # pktlossnum = 0
  # rttnum = 0
  # pkts_invol = 0

  dns_query_counter = 0
  dns_res_counter = 0

  events_table = collections.OrderedDict()
  dst_ip_set = set()

  for ts, buf in pcap:
    pkts_counter += 1
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
      if udp.dport == 53:
        dns = dpkt.dns.DNS(udp.data)

        if dns.opcode != dpkt.dns.DNS_QUERY :
          print "A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode
          continue

        if dns.qr != dpkt.dns.DNS_Q :
          print "A DNS packet was sent to the name server, but dns.qr is not 0 and should be.  It is %d" % dns.qr
          continue

        if dns.qd[0].cls != dpkt.dns.DNS_IN:
          continue

        if dns.qd[0].type != dpkt.dns.DNS_A:
          continue

        if my_src_ip == "":
          my_src_ip = socket.inet_ntoa(ip.src)
          print "My src_ip is:", my_src_ip

        print "query for ", dns.qd[0].name, "ID is ", dns.id, "dns.qr is ", dns.qr, "query type is ", dns.qd[0].type
        print "dns.qd is ", dns.qd



        events_table["DNS_" + str(dns.id)] = {"start_time":ts,
                                              "end_time":0,
                                              "src_ip":srcip,
                                              "dst_ip":dstip,
                                              "bytes_involved":ip.len,
                                              "packets_involved":1,
                                              "rtt_num":0,
                                              "packets_loss":0,
                                              }

        dns_query_counter += 1


      elif udp.sport == 53:
        # This is an DNS response.
        dns = dpkt.dns.DNS(udp.data)
        print "responding to ", dns.id, "dns.qr is ", dns.qr

        if dns.opcode != dpkt.dns.DNS_QUERY :
          print "A DNS packet was sent to the nameserver, but the opcode was %d instead of DNS_QUERY (this is a software error)" % dns.opcode
          continue

        if dns.qr != dpkt.dns.DNS_R :
          print "A DNS packet was received from a name server, but dns.qr is not 1 and should be.  It is %d" % dns.qr
          continue

        if len(dns.an) < 1:
          continue

        if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
          continue

        dns_res_counter += 1

        for res in dns.an:
          res_type = res.type
          res_data = res.rdata

          if res_type == dpkt.dns.DNS_CNAME:
            print "Response is a CNAME "

          elif res_type == dpkt.dns.DNS_A:
            ipaddr = socket.inet_ntoa(res_data)
            print "Response is an IPv4 address", ipaddr
            dst_ip_set.add(ipaddr)

          elif res_type == dpkt.dns.DNS_PTR:
            print "Response is hostname from IP address"

          elif res_type == dpkt.dns.DNS_AAAA :
            print "response is an IPv6 address", socket.inet_ntop(socket.AF_INET6, res_data )

          key = "DNS_" + str(dns.id)
          if key not in events_table:
            continue
          events_table[key]["end_time"] = ts
          events_table[key]["packets_involved"] += 1
          events_table[key]["bytes_involved"] += ip.len


    if





  return events_table



















    if ip.p != dpkt.ip.IP_PROTO_TCP:
      continue

    tcp = ip.data
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

    print pkts_counter, "\t", tcp.sport, "\t", tcp.dport, "\t", flags
    conn_id = (ip.src, tcp.sport, ip.dst, tcp.dport)

    if syn_flag and not ack_flag:
      print ts, ":", "New TCP connection is establishing", conn_id_to_str(conn_id, ip.v)

    elif