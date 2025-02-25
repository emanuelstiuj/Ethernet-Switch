# Ethernet Switch

This solution implements an Ethernet switch that manages traffic and uses the Spanning Tree Protocol (STP) to prevent network loops. The code is structured into multiple functions and modules to configure and control the state of each port based on received BPDU messages.

### Brief Explanation of Functions and Components:

- **parse_ethernet_header(data):**  
  Extracts fields from an Ethernet packet (destination MAC, source MAC, protocol type, and VLAN ID if present).

- **create_vlan_tag(vlan_id):**  
  Creates a VLAN tag for Ethernet packets using the specific VLAN format.

- **switch_config_func(filename):**  
  Reads a switch configuration file, initializing priority settings and configuring access and trunk ports.

- **set_port_state(port, state):**  
  Updates the state of each port (DESIGNATED or BLOCKING).

- **handle_received_bpdu(bpdu, received_port, switch_config, interfaces):**  
  This is a core function for STP implementation. Upon receiving a BPDU, the function evaluates whether the received BPDU indicates a better route to the STP root bridge, ensuring loop prevention and determining which ports should be blocked or unblocked.

- **create_bpdu_frame(root_bridge_id, sender_bridge_id, root_path_cost):**  
  Creates the BPDU frame with necessary STP information.

- **send_bpdu_every_sec(switch_config, interfaces):**  
  Periodically sends BPDU packets on trunk ports to maintain the spanning tree structure.

- **main():**  
  Initializes the switch (BPDU data, forwarding table) and starts the configuration and BPDU transmission processes. It also manages packet forwarding based on VLAN configurations and handles interface setup and BPDU message exchange.

