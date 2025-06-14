import socket
import struct
import random
import time
import threading
from datetime import datetime
import ipaddress
import numpy as np

class NetworkTrafficGenerator:
    """
    Advanced network traffic generator that creates realistic packet flows
    This simulates network-level traffic without requiring actual packet injection
    """
    
    def __init__(self):
        self.is_running = False
        self.traffic_patterns = {
            'web_browsing': {
                'protocols': ['tcp'],
                'dst_ports': [80, 443, 8080, 8443],
                'packet_sizes': (64, 1500),
                'duration_range': (0.1, 30.0),
                'frequency': 0.3
            },
            'email': {
                'protocols': ['tcp'],
                'dst_ports': [25, 110, 143, 993, 995],
                'packet_sizes': (100, 4096),
                'duration_range': (1.0, 120.0),
                'frequency': 0.1
            },
            'dns': {
                'protocols': ['udp'],
                'dst_ports': [53],
                'packet_sizes': (64, 512),
                'duration_range': (0.1, 2.0),
                'frequency': 0.2
            },
            'ssh': {
                'protocols': ['tcp'],
                'dst_ports': [22],
                'packet_sizes': (64, 2048),
                'duration_range': (60.0, 3600.0),
                'frequency': 0.05
            },
            'ftp': {
                'protocols': ['tcp'],
                'dst_ports': [20, 21],
                'packet_sizes': (64, 8192),
                'duration_range': (10.0, 600.0),
                'frequency': 0.02
            }
        }
        
        # Network ranges for realistic IP generation
        self.internal_networks = [
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12')
        ]
        
        self.external_networks = [
            ipaddress.IPv4Network('8.8.8.0/24'),      # Google DNS
            ipaddress.IPv4Network('1.1.1.0/24'),      # Cloudflare
            ipaddress.IPv4Network('208.67.222.0/24'), # OpenDNS
            ipaddress.IPv4Network('13.107.42.0/24'),  # Microsoft
            ipaddress.IPv4Network('31.13.64.0/24')    # Facebook
        ]
    
    def generate_realistic_ip(self, internal=True):
        """Generate realistic IP addresses"""
        if internal:
            network = random.choice(self.internal_networks)
        else:
            network = random.choice(self.external_networks)
        
        # Generate random IP within the network
        network_int = int(network.network_address)
        broadcast_int = int(network.broadcast_address)
        random_int = random.randint(network_int + 1, broadcast_int - 1)
        
        return str(ipaddress.IPv4Address(random_int))
    
    def generate_connection_flow(self):
        """Generate a realistic network connection flow"""
        # Select traffic pattern
        pattern_name = random.choices(
            list(self.traffic_patterns.keys()),
            weights=[p['frequency'] for p in self.traffic_patterns.values()]
        )[0]
        
        pattern = self.traffic_patterns[pattern_name]
        
        # Generate connection details
        src_ip = self.generate_realistic_ip(internal=True)
        dst_ip = self.generate_realistic_ip(internal=random.choice([True, False]))
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(pattern['dst_ports'])
        protocol = random.choice(pattern['protocols'])
        
        # Generate flow characteristics
        duration = random.uniform(*pattern['duration_range'])
        packet_count = random.randint(5, 100)
        total_bytes = random.randint(*pattern['packet_sizes']) * packet_count
        
        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'duration': duration,
            'src_bytes': total_bytes // 2 + random.randint(-100, 100),
            'dst_bytes': total_bytes // 2 + random.randint(-100, 100),
            'packet_count': packet_count,
            'pattern': pattern_name,
            'timestamp': datetime.now()
        }
    
    def simulate_attack_traffic(self):
        """Generate attack-like traffic patterns"""
        attack_patterns = {
            'port_scan': {
                'src_ip': self.generate_realistic_ip(internal=False),
                'dst_ip': self.generate_realistic_ip(internal=True),
                'dst_ports': list(range(1, 1024)),  # Scanning common ports
                'duration': random.uniform(0.01, 0.1),  # Very short connections
                'src_bytes': random.randint(0, 100),
                'dst_bytes': 0,
                'protocol': 'tcp'
            },
            'dos_attack': {
                'src_ip': self.generate_realistic_ip(internal=False),
                'dst_ip': self.generate_realistic_ip(internal=True),
                'dst_ports': [80, 443],
                'duration': random.uniform(0.01, 1.0),
                'src_bytes': random.randint(1000, 10000),  # Large packets
                'dst_bytes': random.randint(0, 100),
                'protocol': 'tcp'
            },
            'brute_force': {
                'src_ip': self.generate_realistic_ip(internal=False),
                'dst_ip': self.generate_realistic_ip(internal=True),
                'dst_ports': [22, 21, 23],  # SSH, FTP, Telnet
                'duration': random.uniform(1.0, 5.0),
                'src_bytes': random.randint(100, 500),
                'dst_bytes': random.randint(50, 200),
                'protocol': 'tcp'
            }
        }
        
        attack_type = random.choice(list(attack_patterns.keys()))
        pattern = attack_patterns[attack_type]
        
        # For port scan, generate multiple connections
        if attack_type == 'port_scan':
            connections = []
            base_time = datetime.now()
            for i in range(random.randint(10, 50)):
                conn = {
                    'src_ip': pattern['src_ip'],
                    'dst_ip': pattern['dst_ip'],
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice(pattern['dst_ports']),
                    'protocol': pattern['protocol'],
                    'duration': pattern['duration'],
                    'src_bytes': pattern['src_bytes'],
                    'dst_bytes': pattern['dst_bytes'],
                    'attack_type': attack_type,
                    'timestamp': base_time
                }
                connections.append(conn)
            return connections
        else:
            return [{
                'src_ip': pattern['src_ip'],
                'dst_ip': pattern['dst_ip'],
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice(pattern['dst_ports']),
                'protocol': pattern['protocol'],
                'duration': pattern['duration'],
                'src_bytes': pattern['src_bytes'],
                'dst_bytes': pattern['dst_bytes'],
                'attack_type': attack_type,
                'timestamp': datetime.now()
            }]
    
    def start_generation(self, callback_func):
        """Start generating network traffic"""
        self.is_running = True
        
        def generate_traffic():
            while self.is_running:
                # Generate normal traffic (80% of the time)
                if random.random() < 0.8:
                    flow = self.generate_connection_flow()
                    callback_func([flow])
                else:
                    # Generate attack traffic (20% of the time)
                    attack_flows = self.simulate_attack_traffic()
                    callback_func(attack_flows)
                  # Variable delay to simulate realistic traffic patterns
                delay = np.random.exponential(0.5)  # Exponential distribution for realistic timing
                time.sleep(min(delay, 2.0))  # Cap at 2 seconds
        
        self.thread = threading.Thread(target=generate_traffic, daemon=True)
        self.thread.start()
    
    def stop_generation(self):
        """Stop generating traffic"""
        self.is_running = False
