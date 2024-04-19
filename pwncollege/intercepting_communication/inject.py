"""
Script to sniff network packets, modify specific content, and send a response packet.

This script listens for incoming packets on the 'eth0' interface. When a TCP packet with raw data is received,
it checks if the data matches a specific content pattern. If it does, the script modifies the content and sends
a response packet back to the sender.
"""

from scapy.all import sniff, sendp, Ether, IP, TCP, Raw

def process_packet(packet):
    """
    Process the received packet.

    Args:
        packet (scapy.packet): The received packet.
    """
    if TCP not in packet or Raw not in packet:
        return

    data = packet[Raw].load.decode()
    print(packet)
    print(" " + repr(data))

    if data == 'content_to_modify\n':
        response_packet = (
            Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
            IP(src=packet[IP].dst, dst=packet[IP].src) /
            TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, seq=packet[TCP].ack, ack=packet[TCP].seq + len(data), flags="PA") /
            b"modified_content\n"
        )
        sendp(response_packet, iface="eth0")

sniff(prn=process_packet, iface="eth0")
