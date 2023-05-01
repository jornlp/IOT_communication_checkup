# id = streamKey, value = list of matching packets
TCP_capture_dictionary = {}
UDP_capture_dictionary = {}


# streamnr: [host, dst_port, protocol, ip_dst, [cipher, version, []]
stream_dst_ip_dictionary_TCP = {}
stream_dst_ip_dictionary_UDP = {}



#Todo: streamnr: cipher, version, verified, host, ip
cipher_TLSVersion_verified_dictionary = {}

host_set = set()



# streamnr: host, report string
host_report_output_normal_TCP = {}
host_report_output_normal_UDP = {}
