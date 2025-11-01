from scapy.all import *

class SimulationHandler:
    """
    A handler for creating and managing a simulated network environment.
    """

    def __init__(self):
        self.nodes = {}
        self.links = []

    def add_node(self, name, type):
        """
        Adds a new node to the simulation.
        """
        self.nodes[name] = {"type": type, "interfaces": {}}

    def add_link(self, node1, node2):
        """
        Adds a new link between two nodes.
        """
        self.links.append((node1, node2))

    def get_node(self, name):
        """
        Retrieves a node from the simulation.
        """
        return self.nodes.get(name)

    def get_links(self):
        """
        Retrieves all links in the simulation.
        """
        return self.links

    def run_command(self, node_name, command):
        """
        Simulates the execution of a command on a network device.
        """
        node = self.get_node(node_name)
        if not node:
            return f"Error: Node '{node_name}' not found in the simulation."

        if command == "show running-config":
            return f"Running configuration for {node_name}:\n\n! interface GigabitEthernet0/1\n ip address 192.168.1.1 255.255.255.0\n no shutdown\n!"
        elif command == "show ip interface brief":
            return f"Interface IP-Address OK? Method Status Protocol\nGigabitEthernet0/1 192.168.1.1 YES manual up up"
        else:
            return f"Error: Command '{command}' not supported in the simulation."
