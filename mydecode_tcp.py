import dpkt
import sys
import socket
import collections

# TCP handshake status
TCP_FHS = 1
TCP_SHS = 2
TCP_THS = 3


def conn_id_to_str(cid):
  '''
  cid = (srcip, sport, dstip, dport)
  :param cid:
  :return:
  '''
  return cid[0] + ':' + str(cid[1]) + "<=>" + cid[2] + ':' + cid[3]


def UDP_info(buf):
  pass


def main(file):
  pcap = dpkt.pcap.Reader(file)

  my_src_ip = ""

  pkts_counter = 0
  # pktlossnum = 0
  # rttnum = 0
  # pkts_invol = 0

  tcp_conn_state = {}

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
                                              "packets_loss":0
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


    # my_src_ip is updated in DNS request part.
    if ip.p == dpkt.ip.IP_PROTO_TCP and my_src_ip != "" :
      if srcip not in dst_ip_set and dstip not in dst_ip_set:
        print "Unknown src or dst ip address."
        continue

      tcp = ip.data

      if my_src_ip == srcip:
        conn_id = (srcip, tcp.sport, dstip, tcp.dport)
        conn_header = conn_id_to_str(conn_id)
      else:
        conn_id = (dstip, tcp.sport, srcip, tcp.dport)
        conn_header = conn_id_to_str(conn_id)

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

      if conn_header not in tcp_conn_state:
        # First TCP handshake.
        if syn_flag and not ack_flag:
          print "New TCP connection is establishing..."
          events_table["TCP_" + conn_header] = {"start_time":ts,
                                              "end_time":0,
                                              "src_ip":srcip,
                                              "dst_ip":dstip,
                                              "bytes_involved":ip.len,
                                              "packets_involved":1,
                                              "rtt_num":0,
                                              "packets_loss":0
                                              }
          tcp_conn_state[conn_header] = {}
          # waiting for the second handshake
          tcp_conn_state[conn_header]["src_waiting_ack"] = [tcp.seq]
          tcp_conn_state[conn_header]["src_starting_seqnum"] = tcp.seq
          tcp_conn_state[conn_header]["tcp_req_counter"] = 0
          tcp_conn_state[conn_header]["status"] = TCP_FHS

        else:
          print "No record for this TCP connection. Pass"

      # second tcp handshake.
      elif syn_flag and ack_flag:
        if tcp_conn_state[conn_header]["status"] == TCP_FHS:
          events_table["TCP_" + conn_header]["bytes_involved"] += ip.len
          events_table["TCP_" + conn_header]["packets_involved"] += 1
          events_table["TCP_" + conn_header]["rtt_num"] += 1

          # clear the waiting flag for the first handshake
          tcp_conn_state[conn_header]["src_waiting_ack"].remove(ack_flag-1)
          tcp_conn_state[conn_header]["status"] = TCP_SHS
          # Waiting for the 3rd handshake
          tcp_conn_state[conn_header]["dst_waiting_ack"] = [tcp.seq]
          tcp_conn_state[conn_header]["dst_starting_seqnum"] = tcp.seq

        else:
          # second handshake packet loss.
          print "second handshake packet loss"
          events_table["TCP_" + conn_header]["packets_loss"] += 1

      # simply check ack_flag won't work.
          # elif not syn_flag and ack_flag:

      elif tcp_conn_state[conn_header]["status"] == TCP_SHS and len(tcp.data) == 0:
        events_table["TCP_" + conn_header]["bytes_involved"] += ip.len
        events_table["TCP_" + conn_header]["packets_involved"] += 1
        events_table["TCP_" + conn_header]["rtt_num"] += 1
        events_table["TCP_" + conn_header]["end_time"] = ts

        if tcp.ack-1 in tcp_conn_state[conn_header]["dst_waiting_ack"]:
          tcp_conn_state[conn_header]["dst_waiting_ack"].remove(tcp.ack-1)
        tcp_conn_state[conn_header]["status"] = TCP_THS

        print "New TCP connection is established."

      # object request and response
      elif tcp_conn_state[conn_header]["status"] == TCP_THS:
        # http request
        if tcp.dport == 80:
          # object request
          if len(tcp.data) > 0:
            if tcp.seq + len(tcp.data) not in tcp_conn_state[conn_header]["src_waiting_ack"]:
              tcp_conn_state[conn_header]["src_waiting_ack"].append(tcp.seq + len(tcp.data))
              tcp_conn_state[conn_header]["tcp_req_counter"] += 1

              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])
              events_table[object_event] = {"start_time":ts,
                                              "end_time":0,
                                              "src_ip":srcip,
                                              "dst_ip":dstip,
                                              "bytes_involved":ip.len,
                                              "packets_involved":1,
                                              "rtt_num":0,
                                              "packets_loss":0
                                           }

            else:
              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])
              events_table[object_event]["packets_loss"] += 1
              events_table[object_event]["packets_involved"] += 1
              events_table[object_event]["rtt_num"] += 1
              events_table[object_event]["bytes_involved"] += ip.len

              print "Http response ack is resent."

          # response ack
          else:
            if tcp.ack in tcp_conn_state[conn_header]["dst_waiting_ack"]:
              tcp_conn_state[conn_header]["dst_waiting_ack"].remove(tcp.ack)

              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])

              events_table[object_event]["end_time"] = ts
              events_table[object_event]["bytes_involved"] += ip.len
              events_table[object_event]["packets_involved"] += 1
              events_table[object_event]["rtt_num"] += 1

            elif len(tcp_conn_state[conn_header]["dst_waiting_ack"]) == 0 \
              or tcp.ack > max(tcp_conn_state[conn_header]["dst_waiting_ack"]):
              continue

            else:
              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])
              events_table[object_event]["packets_loss"] += 1
              events_table[object_event]["packets_involved"] += 1

              print "object response ack is resent."

        elif tcp.sport == 80:

          if len(tcp.data) > 0:

            if tcp.seq + len(tcp.data) not in tcp_conn_state[conn_header]["dst_waiting_ack"]:
              tcp_conn_state[conn_header]["dst_waiting_ack"].append(tcp.seq + len(tcp.data))

              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])
              events_table[object_event]["packets_involved"] += 1
              events_table[object_event]["rtt_num"] += 1
              events_table[object_event]["end_time"] = ts
              events_table[object_event]["bytes_involved"] += ip.len

            else:
              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])
              events_table[object_event]["packets_loss"] += 1

              print "Http response is resent."


          # response ack
          else:
            if tcp.ack in tcp_conn_state[conn_header]["src_waiting_ack"]:
              tcp_conn_state[conn_header]["src_waiting_ack"].remove(tcp.ack)

              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])

              events_table[object_event]["end_time"] = ts
              events_table[object_event]["bytes_involved"] += ip.len
              events_table[object_event]["packets_involved"] += 1
              events_table[object_event]["rtt_num"] += 1

            elif len(tcp_conn_state[conn_header]["src_waiting_ack"]) == 0 \
              or tcp.ack > max(tcp_conn_state[conn_header]["src_waiting_ack"]):
              continue

            else:
              object_event = "Object_request_" + conn_header + "_" + str(tcp_conn_state[conn_header]["tcp_req_counter"])
              events_table[object_event]["packets_loss"] += 1
              events_table[object_event]["packets_involved"] += 1

              print "object response ack is resent."

        else:
          print "Counld not resolve this HTTP packet."

      else:
        print "Could not handle this tcp status."


  print "-------------------------"
  print "Total number of packets:", pkts_counter
  print "-------------------------"

  return events_table


if __name__ == '__main__':
  f = open(sys.argv[1])
  main(f)





















