#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Parses the Ethernet header and extracts the MAC addresses, EtherType, and VLAN ID if present
def parse_ethernet_header(data):
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]
    
    vlan_id = -1
    if ether_type == 0x8200:  # Check if there's a VLAN tag
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

# Creates a VLAN tag for a given VLAN ID
def create_vlan_tag(vlan_id):
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# Checks if the MAC address is a broadcast address
def is_broadcast(mac_addr):
    return mac_addr == b'\xff\xff\xff\xff\xff\xff'

# Reads switch configuration from the file
def switch_config_func(filename):
    switch_config = {
        "switch_priority": None,
        "access_ports": {},
        "trunk_ports": []
    }

    with open(filename, 'r') as f:
        switch_config["switch_priority"] = int(f.readline().strip())
        
        for line in f:
            parts = line.strip().split()
            interface = parts[0]
            vlan = parts[1]
            
            if vlan.isdigit():
                switch_config["access_ports"][interface] = int(vlan)
            else:
                switch_config["trunk_ports"].append(interface)

    return switch_config

# Port states and spanning tree configuration for the switch
port_states = {}
switch_bpd = {}

# Sets the state of a given port
def set_port_state(port, state):
    port_states[port] = state

# Handles a received BPDU, adjusting the spanning tree configuration
def handle_received_bpdu(bpdu, received_port, switch_config, interfaces):
    bpdu_root_bridge_id = bpdu["root_bridge_id"]
    bpdu_sender_bridge_id = bpdu["sender_bridge_id"]
    bpdu_sender_path_cost = bpdu["root_path_cost"]
    
    # Updates root bridge information if BPDU contains a new root bridge
    if bpdu_root_bridge_id < switch_bpd["root_bridge_id"]:
        old_root_bridge_id = switch_bpd["root_bridge_id"]
        switch_bpd["root_bridge_id"] = bpdu_root_bridge_id
        switch_bpd["root_path_cost"] = bpdu_sender_path_cost + 10
        switch_bpd["root_port"] = received_port

        # Set trunk ports to BLOCKING if the local switch is no longer root
        if switch_bpd["own_bridge_id"] == old_root_bridge_id:
            for intf in interfaces:
                if get_interface_name(intf) in switch_config["trunk_ports"] and intf != received_port:
                    set_port_state(intf, "BLOCKING")

        # Designate the received port if it was blocking
        if port_states[received_port] == "BLOCKING":
            set_port_state(received_port, "DESIGNATED")

        # Generate and broadcast updated BPDU
        updated_bpdu = {
            "root_bridge_id": switch_bpd["root_bridge_id"],
            "sender_bridge_id": switch_bpd["own_bridge_id"],
            "sender_path_cost": switch_bpd["root_path_cost"]
        }
        
        for intf in interfaces:
            if get_interface_name(intf) in switch_config["trunk_ports"] and intf != received_port:
                bpdu_frame = create_bpdu_frame(
                    updated_bpdu["root_bridge_id"],
                    updated_bpdu["sender_bridge_id"],
                    updated_bpdu["sender_path_cost"]
                )
                send_to_link(intf, len(bpdu_frame), bpdu_frame)
    
    # Adjusts path cost or port state if BPDU is from the current root bridge
    elif bpdu_root_bridge_id == switch_bpd["root_bridge_id"]:
        if received_port == switch_bpd["root_port"] and (bpdu_sender_path_cost + 10 < switch_bpd["root_path_cost"]):
            switch_bpd["root_path_cost"] = bpdu_sender_path_cost + 10
        elif received_port != switch_bpd["root_port"]:
            if bpdu_sender_path_cost > switch_bpd["root_path_cost"]:
                if port_states[received_port] != "DESIGNATED":
                    set_port_state(received_port, "DESIGNATED")
    
    # Blocks port if BPDU is from the same bridge ID
    elif bpdu_sender_bridge_id == switch_bpd["own_bridge_id"]:
        set_port_state(received_port, "BLOCKING")
    
    # If the switch is the root bridge, designate all ports
    if switch_bpd["own_bridge_id"] == switch_bpd["root_bridge_id"]:
        for intf in interfaces:
            set_port_state(intf, "DESIGNATED")

# Creates a BPDU frame for sending
def create_bpdu_frame(root_bridge_id, sender_bridge_id, root_path_cost):
    flags = 0x00
    protocol_identifier = 0x0000
    protocol_version = 0x00     
    bpdu_type = 0x00            

    bpdu_payload = struct.pack(
        '!HBBB8sI8sHHHHH',
        protocol_identifier, 
        protocol_version,         
        bpdu_type,
        flags,                           
        root_bridge_id.to_bytes(8, 'big'),
        root_path_cost,                  
        sender_bridge_id.to_bytes(8, 'big'),
        0,                               
        0,                               
        20,                              
        2,                               
        15                               
    )

    dsap = 0x42
    ssap = 0x42
    control = 0x03
    llc_header = struct.pack('!BBB', dsap, ssap, control)

    total_length = len(llc_header) + len(bpdu_payload)
    llc_length = struct.pack('!H', total_length) 
    
    dest_mac = b'\x01\x80\xc2\x00\x00\x00'
    src_mac = get_switch_mac()

    eth_frame = (
        dest_mac + 
        src_mac + 
        llc_length +
        llc_header + 
        bpdu_payload
    )

    return eth_frame

# Sends BPDUs every second if the switch is the root bridge
def send_bpdu_every_sec(switch_config, interfaces):
    while True:
        if switch_bpd["own_bridge_id"] == switch_bpd["root_bridge_id"]:
            bpdu_frame = create_bpdu_frame( 
                switch_bpd["own_bridge_id"],
                switch_bpd["own_bridge_id"],
                0
            )
            for intf in interfaces:
                if get_interface_name(intf) in switch_config["trunk_ports"]:
                    send_to_link(intf, len(bpdu_frame), bpdu_frame)
        time.sleep(1)

def main():
    switch_id = sys.argv[1]
    switch_config = switch_config_func("./configs/switch" + switch_id + ".cfg")
    
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    for intf in interfaces:
        if get_interface_name(intf) in switch_config["trunk_ports"]:
            set_port_state(intf, "BLOCKING")
        else:
            set_port_state(intf, "DESIGNATED")
    
    # Initialize switch bridge data
    switch_bpd["own_bridge_id"] = switch_config["switch_priority"]
    switch_bpd["root_bridge_id"] = switch_config["switch_priority"]
    switch_bpd["root_path_cost"] = 0
    
    # Set all ports to DESIGNATED if switch is root bridge
    if switch_bpd["own_bridge_id"] == switch_bpd["root_bridge_id"]:
        for intf in interfaces:
            set_port_state(intf, "DESIGNATED")

    t = threading.Thread(target=send_bpdu_every_sec, args=(switch_config, interfaces))
    t.start()

    mac_table = {}

    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        mac_table[src_mac] = interface

        # Process BPDU frames to handle spanning tree protocol
        if dest_mac == b'\x01\x80\xc2\x00\x00\x00':
            bpdu = {
                "root_bridge_id": int.from_bytes(data[22:30], byteorder='big'),
                "root_path_cost": int.from_bytes(data[30:34], byteorder='big'),
                "sender_bridge_id": int.from_bytes(data[34:42], byteorder='big'),
            }
            handle_received_bpdu(bpdu, interface, switch_config, interfaces)

        # For frames with known destination MAC and no VLAN, handle switching and tagging
        elif dest_mac in mac_table and vlan_id == -1:
            vlan_src = switch_config["access_ports"].get(get_interface_name(interface))
            intf_dest = mac_table[dest_mac]
            if get_interface_name(intf_dest) in switch_config["access_ports"]:
                vlan_dest = switch_config["access_ports"].get(get_interface_name(intf_dest))
                if vlan_dest == vlan_src:
                    send_to_link(intf_dest, length, data)
            elif port_states[intf_dest] != "BLOCKING":
                tagged_frame = data[0:12] + create_vlan_tag(vlan_src) + data[12:]
                send_to_link(intf_dest, length + 4, tagged_frame)

        # Broadcast frames to all relevant interfaces if VLAN is unknown
        elif vlan_id == -1:
            vlan_src = switch_config["access_ports"].get(get_interface_name(interface))

            for intf in interfaces:
                if get_interface_name(intf) in switch_config["access_ports"]:
                    vlan_dest = switch_config["access_ports"].get(get_interface_name(intf))
                    if vlan_dest == vlan_src and intf != interface:
                        send_to_link(intf, length, data)

            tagged_frame = data[0:12] + create_vlan_tag(vlan_src) + data[12:]
            for intf in interfaces:
                if get_interface_name(intf) in switch_config["trunk_ports"]:
                    if intf != interface and port_states[intf] != "BLOCKING":
                        send_to_link(intf, length + 4, tagged_frame)

        # Handle frames with known destination MAC and VLAN tagging
        elif dest_mac in mac_table and vlan_id != -1:
            vlan_src = vlan_id
            intf_dest = mac_table[dest_mac]
            if get_interface_name(intf_dest) in switch_config["access_ports"]:
                vlan_dest = switch_config["access_ports"].get(get_interface_name(intf_dest))
                if vlan_dest == vlan_src:
                    untagged_frame = data[0:12] + data[16:]
                    send_to_link(intf_dest, length - 4, untagged_frame)
            elif port_states[intf_dest] != "BLOCKING":
                send_to_link(intf_dest, length, data)

        # For broadcast frames with VLAN, handle tagging and broadcast
        elif vlan_id != -1:
            vlan_src = vlan_id

            for intf in interfaces:
                if get_interface_name(intf) in switch_config["access_ports"]:
                    vlan_dest = switch_config["access_ports"].get(get_interface_name(intf))
                    untagged_frame = data[0:12] + data[16:]
                    if vlan_dest == vlan_src and intf != interface:
                        send_to_link(intf, length - 4, untagged_frame)

            for intf in interfaces:
                if get_interface_name(intf) in switch_config["trunk_ports"]:
                    if intf != interface and port_states[intf] != "BLOCKING":
                        send_to_link(intf, length, data)

if __name__ == "__main__":
    main()
