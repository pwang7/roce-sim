import socket
import struct

from multiprocessing import Process
from scapy.all import *
#from scapy.contrib.roce import BTH, AETH, opcode
from roce import BTH, AETH, RETH, opcode

DST_IP = '192.168.122.190'
SRC_IP = '192.168.122.238'
ROCE_PORT = 4791
#DST_PORT = 9527
SRC_PORT = 9527
UDP_BUF_SIZE = 1024

S_VA = '0000556acaa2ea50'
S_RKEY = '00000208'
S_QPN = '00000011'
S_LID = '0000'
#S_GID = 'fe80000000000000505400fffea7d042'
S_GID = '00000000000000000000ffffc0a87aee'

src_cpsn = 0
src_epsn = 0

# Wait for connection
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_bind_addr = ('0.0.0.0', SRC_PORT)
udp_sock.bind(server_bind_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<c', exch_data))
udp_sock.sendto(struct.pack('c', b'2'), peer_addr)

# Send metadata
server_metadata = S_VA + S_RKEY + S_QPN + S_LID + S_GID
udp_sock.sendto(bytes.fromhex(server_metadata), peer_addr)

# Recive metadata
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack('>QIIH16s', exch_data)
dst_va, dst_rkey, dst_qpn, dst_lid, dst_gid = parsed_fields
print(parsed_fields)

# Exchange receive ready
udp_sock.sendto(struct.pack('<i', 0), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<i', exch_data))

# RoCE send and ack
send_str = 'RDMA_Send_Operation'
send_size = len(send_str)
send_bth = BTH(
    opcode = opcode('RC', 'SEND_ONLY')[0],
    psn = src_cpsn,
    dqpn = dst_qpn,
    ackreq = True,
)
send_data = struct.pack(f'<{send_size}s', bytearray(send_str, 'ascii'))
send_req = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/send_bth/Raw(load=send_data)
ans, unans = sr(send_req, multi=False, timeout=1)
assert len(ans) == 1, 'should receive 1 send response packet'
send_resp = ans[0].answer
send_resp.show()
assert send_resp.psn == src_cpsn, 'write response PSN not match'
src_cpsn += 1

# Exchange send size
udp_sock.sendto(struct.pack('<iq', 1, send_size), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
print(struct.unpack('<iq', exch_data))

# Exchange read size
read_str = 'RDMA_Read_Operation'
udp_sock.sendto(struct.pack('<iq', 2, len(read_str)), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack('<iq', exch_data)
_, read_size = parsed_fields
print(parsed_fields)

# RoCE read and ack
roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
read_req = roce_pkts[0]
read_req.show()
assert read_req[BTH].psn == src_epsn, 'expected PSN not match'
src_epsn += 1
read_resp_bth = BTH(
    opcode = opcode('RC', 'RDMA_READ_RESPONSE_ONLY')[0],
    psn = read_req[BTH].psn,
    dqpn = dst_qpn,
)
read_size = read_req[RETH].dlen
print(f'read size = {read_size}')
read_data = struct.pack(f'<{read_size}s', bytearray(read_str, 'ascii'))
read_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/read_resp_bth/AETH(code='ACK', value=31, msn=1)/Raw(load=read_data)
send(read_resp)

# RoCE write and ack
roce_pkts = sniff(filter=f'udp port {ROCE_PORT}', count=1)
write_req = roce_pkts[0]
write_req.show()
write_resp_bth = BTH(
    opcode = opcode('RC', 'ACKNOWLEDGE')[0],
    psn = write_req[BTH].psn,
    dqpn = dst_qpn,
)
write_resp = IP(dst=DST_IP)/UDP(dport=ROCE_PORT, sport=ROCE_PORT)/write_resp_bth/AETH(code='ACK', value=31, msn=1)
send(write_resp)

# Exchange write size
udp_sock.sendto(struct.pack('<iq', 3, -1), peer_addr)
exch_data, peer_addr = udp_sock.recvfrom(UDP_BUF_SIZE)
parsed_fields = struct.unpack('<iq', exch_data)
print(parsed_fields)



udp_sock.close()

