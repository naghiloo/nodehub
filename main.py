import threading
from scapy.all import *
import logging

# Set up logging
logging.basicConfig(filename="logs.log", level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger(__name__)

class Node:
    def __init__(self, name, ip, nodes):
        self.name = name
        self.ip = ip
        self.nodes = nodes
        self.messages = []

    def server(self):
        self.messages = []
        def icmp_packet_callback(packet):
            if packet.haslayer(ICMP):
                print("ICMP packet received:")
                print("  Type:", packet[ICMP].type)
                print("  Code:", packet[ICMP].code)
                print("  Checksum:", packet[ICMP].chksum)
                print("  ID:", packet[ICMP].id)
                print("  Sequence:", packet[ICMP].seq)
                print("  Message:", packet[Raw].load)
                self.messages.append(packet[Raw].load)

        sniff(prn=icmp_packet_callback, filter="icmp")

    def client(self, target_ip, data):
        packet = IP(dst=target_ip) / ICMP() / data
        send(packet)

    def start_server(self):
        server_thread = threading.Thread(target=self.server)
        server_thread.start()

    def start_client(self):
        for node in self.nodes:
            if node != self:
                self.client(node.ip, f"Hello, {node.name}")

def select_destination_node(nodes):
    print("Available Nodes:")
    for i, node in enumerate(nodes):
        print(f"{i + 1}. {node.name}")

    while True:
        try:
            choice = int(input("Enter the number of the destination node: "))
            if 1 <= choice <= len(nodes):
                return nodes[choice - 1]
            else:
                print("Invalid choice. Please enter a valid node number.")
        except ValueError:
            print("Invalid input. Please enter a valid node number.")

def main():
    
    this = Node("NodeA", "127.0.0.1", [])

    nodes = [
        Node("NodeB", "node-2-ip", []),
        # Node("NodeC", "192.168.10.10", []),
    ]

    nodes.insert(0, this)

    for node in nodes:
        # list of other nodes except current one.
        # It's the list of nodes that can communicate
        node.nodes = [other_node for other_node in nodes] #if other_node != node]
    
    this.start_server()
    this.start_client()

    while True:
        destination_node = select_destination_node(nodes)
        message = input("Enter your message: ")
        destination_node.client(destination_node.ip, message)
        print("Sent message:", message)

        # Print all received messages
        for message in this.messages:
            print("Received message:", message)

if __name__ == "__main__":
    main()
