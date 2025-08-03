#!/usr/bin/env python3
"""
Simple TFTP Server with Extensions
- Supports multiple concurrent connections
- Directory traversal protection
- Configuration file support
- TFTP Options Extension (RFC 2347) for large block sizes
- Proper netascii mode support
"""

import socket
import struct
import os
import sys
import argparse
import threading
import configparser
import logging

# Default TFTP Constants
TFTP_PORT = 69
DEFAULT_BLOCK_SIZE = 512
MAX_BLOCK_SIZE = 65464  # Max size that fits in UDP packet
TIMEOUT = 5  # seconds
MAX_RETRIES = 3

# TFTP Opcodes
OP_RRQ = 1    # Read request
OP_WRQ = 2    # Write request
OP_DATA = 3   # Data
OP_ACK = 4    # Acknowledgment
OP_ERROR = 5  # Error
OP_OACK = 6   # Option acknowledgment

# TFTP Error Codes
ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_NO_SUCH_USER = 7
ERR_OPTION_NEGOTIATION = 8

class TFTPServer:
    def __init__(self, config):
        self.config = config
        self.socket = None
        self.running = False
        
        # Setup logging
        log_level = getattr(logging, config.get('server', 'log_level', fallback='INFO'))
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Validate and prepare served file
        self.filename = config.get('server', 'file')
        if not os.path.exists(self.filename):
            raise FileNotFoundError(f"File '{self.filename}' not found")
        
        self.filename = os.path.abspath(self.filename)
        self.file_size = os.path.getsize(self.filename)
        
        # Server settings
        self.port = config.getint('server', 'port', fallback=TFTP_PORT)
        self.timeout = config.getint('server', 'timeout', fallback=TIMEOUT)
        self.retries = config.getint('server', 'retries', fallback=MAX_RETRIES)
        
        # TFTP options
        self.default_blksize = config.getint('tftp', 'default_blksize', fallback=DEFAULT_BLOCK_SIZE)
        self.max_blksize = config.getint('tftp', 'max_blksize', fallback=MAX_BLOCK_SIZE)
        self.allow_options = config.getboolean('tftp', 'allow_options', fallback=True)
        
        self.logger.info(f"Server configured to serve: {self.filename} ({self.file_size} bytes)")
    
    def netascii_encode(self, data):
        """Convert data to netascii format (LF -> CRLF, CR -> CRNUL)"""
        result = bytearray()
        for byte in data:
            if byte == ord('\n'):  # LF -> CRLF
                result.extend(b'\r\n')
            elif byte == ord('\r'):  # CR -> CRNUL
                result.extend(b'\r\x00')
            else:
                result.append(byte)
        return bytes(result)
    
    def start(self):
        """Start the TFTP server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind(('', self.port))
        except OSError as e:
            self.logger.error(f"Cannot bind to port {self.port}: {e}")
            raise
        
        self.running = True
        self.logger.info(f"TFTP Server listening on port {self.port}")
        self.logger.info(f"Serving file: {self.filename}")
        self.logger.info("Press Ctrl+C to stop the server")
        
        try:
            while self.running:
                try:
                    self.socket.settimeout(1.0)
                    try:
                        data, client_addr = self.socket.recvfrom(65536)
                    except socket.timeout:
                        continue
                    
                    # Handle each request in a separate thread
                    thread = threading.Thread(
                        target=self.handle_request,
                        args=(data, client_addr),
                        daemon=True
                    )
                    thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.logger.error(f"Error receiving data: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the TFTP server"""
        self.running = False
        if self.socket:
            self.socket.close()
        self.logger.info("TFTP Server stopped")
    
    def handle_request(self, data, client_addr):
        """Handle incoming TFTP request"""
        if len(data) < 2:
            return
        
        opcode = struct.unpack('!H', data[:2])[0]
        
        if opcode == OP_RRQ:
            self.handle_read_request(data[2:], client_addr)
        elif opcode == OP_WRQ:
            self.send_error(client_addr, ERR_ILLEGAL_OPERATION, 
                           "Write requests not supported")
        else:
            self.send_error(client_addr, ERR_ILLEGAL_OPERATION, 
                           "Unknown operation")
    
    def parse_request(self, data):
        """Parse RRQ/WRQ packet and extract filename, mode, and options"""
        parts = data.split(b'\x00')
        
        if len(parts) < 2:
            return None, None, {}
        
        filename = parts[0].decode('ascii', errors='ignore')
        mode = parts[1].decode('ascii', errors='ignore').lower()
        
        # Parse options (RFC 2347)
        options = {}
        i = 2
        while i + 1 < len(parts):
            opt_name = parts[i].decode('ascii', errors='ignore').lower()
            opt_value = parts[i + 1].decode('ascii', errors='ignore')
            if opt_name and opt_value:
                options[opt_name] = opt_value
            i += 2
        
        return filename, mode, options
    
    def handle_read_request(self, data, client_addr):
        """Handle RRQ (Read Request) with option support"""
        filename, mode, options = self.parse_request(data)
        
        if not filename or not mode:
            self.send_error(client_addr, ERR_NOT_DEFINED, "Invalid request")
            return
        
        self.logger.info(f"Read request from {client_addr}: '{filename}' (mode: {mode})")
        
        # Security: Prevent directory traversal
        if '/' in filename or '\\' in filename or '..' in filename:
            self.logger.warning(f"Directory traversal attempt from {client_addr}: {filename}")
            self.send_error(client_addr, ERR_ACCESS_VIOLATION, "Invalid filename")
            return
        
        # Check if the requested file matches our served file
        if os.path.basename(filename) != os.path.basename(self.filename):
            self.send_error(client_addr, ERR_FILE_NOT_FOUND, f"File not found: {filename}")
            return
        
        # Check mode
        if mode not in ['octet', 'netascii']:
            self.send_error(client_addr, ERR_NOT_DEFINED, f"Mode not supported: {mode}")
            return
        
        # Process options
        negotiated_options = {}
        blksize = self.default_blksize
        
        if self.allow_options and options:
            self.logger.debug(f"Client requested options: {options}")
            
            # Handle blksize option
            if 'blksize' in options:
                try:
                    requested_blksize = int(options['blksize'])
                    if 8 <= requested_blksize <= self.max_blksize:
                        blksize = requested_blksize
                        negotiated_options['blksize'] = str(blksize)
                    else:
                        self.logger.warning(f"Invalid blksize requested: {requested_blksize}")
                except ValueError:
                    self.logger.warning(f"Invalid blksize value: {options['blksize']}")
            
            # Handle tsize option (transfer size)
            if 'tsize' in options and options['tsize'] == '0':
                negotiated_options['tsize'] = str(self.file_size)
        
        # Send file with negotiated options
        self.send_file(client_addr, mode, blksize, negotiated_options)
    
    def send_oack(self, sock, client_addr, options):
        """Send OACK (Option Acknowledgment) packet"""
        if not options:
            return True
        
        oack = struct.pack('!H', OP_OACK)
        for name, value in options.items():
            oack += name.encode('ascii') + b'\x00'
            oack += value.encode('ascii') + b'\x00'
        
        # Send OACK and wait for ACK
        for retry in range(self.retries):
            try:
                sock.sendto(oack, client_addr)
                
                # Wait for ACK to block 0
                ack_data, ack_addr = sock.recvfrom(1024)
                if ack_addr != client_addr:
                    continue
                
                if len(ack_data) >= 4:
                    ack_opcode, ack_block = struct.unpack('!HH', ack_data[:4])
                    if ack_opcode == OP_ACK and ack_block == 0:
                        return True
                    elif ack_opcode == OP_ERROR:
                        return False
            except socket.timeout:
                if retry == self.retries - 1:
                    return False
        
        return False
    
    def send_file(self, client_addr, mode, blksize, options):
        """Send file to client using TFTP protocol"""
        # Create a new socket for this transfer
        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transfer_socket.settimeout(self.timeout)
        
        try:
            # Send OACK if we have negotiated options
            if options:
                if not self.send_oack(transfer_socket, client_addr, options):
                    self.logger.error(f"Failed to negotiate options with {client_addr}")
                    return
                self.logger.info(f"Negotiated options with {client_addr}: {options}")
            
            with open(self.filename, 'rb') as f:
                block_num = 1
                bytes_sent = 0
                
                while True:
                    # Read next block
                    block_data = f.read(blksize)
                    
                    # Convert to netascii if needed
                    if mode == 'netascii':
                        block_data = self.netascii_encode(block_data)
                    
                    # Send DATA packet
                    data_packet = struct.pack('!HH', OP_DATA, block_num) + block_data
                    
                    # Retry logic
                    ack_received = False
                    for retry in range(self.retries):
                        try:
                            transfer_socket.sendto(data_packet, client_addr)
                            
                            # Wait for ACK
                            ack_data, ack_addr = transfer_socket.recvfrom(1024)
                            
                            # Verify sender
                            if ack_addr != client_addr:
                                self.logger.warning(f"Received packet from wrong address: {ack_addr}")
                                continue
                            
                            # Process response
                            if len(ack_data) >= 4:
                                ack_opcode, ack_block = struct.unpack('!HH', ack_data[:4])
                                if ack_opcode == OP_ACK and ack_block == block_num:
                                    ack_received = True
                                    bytes_sent += len(block_data)
                                    break
                                elif ack_opcode == OP_ERROR:
                                    self.logger.warning(f"Client error received")
                                    return
                        except socket.timeout:
                            if retry == self.retries - 1:
                                self.logger.error(f"Timeout on block {block_num}")
                                return
                    
                    if not ack_received:
                        self.logger.error(f"Failed to receive ACK for block {block_num}")
                        return
                    
                    # Check if transfer is complete
                    if len(block_data) < blksize:
                        self.logger.info(f"Transfer complete to {client_addr}: {bytes_sent} bytes")
                        break
                    
                    # Move to next block
                    block_num = (block_num + 1) % 65536  # Wrap around at 65536
                    
                    # Send empty final block if needed
                    if f.tell() == self.file_size and len(block_data) == blksize:
                        data_packet = struct.pack('!HH', OP_DATA, block_num) + b''
                        for retry in range(self.retries):
                            try:
                                transfer_socket.sendto(data_packet, client_addr)
                                ack_data, ack_addr = transfer_socket.recvfrom(1024)
                                if ack_addr == client_addr and len(ack_data) >= 4:
                                    ack_opcode, ack_block = struct.unpack('!HH', ack_data[:4])
                                    if ack_opcode == OP_ACK and ack_block == block_num:
                                        break
                            except socket.timeout:
                                pass
                        break
                    
        except Exception as e:
            self.logger.error(f"Error during transfer to {client_addr}: {e}")
            self.send_error_on_socket(transfer_socket, client_addr, ERR_NOT_DEFINED, str(e))
        finally:
            transfer_socket.close()
    
    def send_error(self, client_addr, error_code, error_msg):
        """Send ERROR packet on main socket"""
        self.send_error_on_socket(self.socket, client_addr, error_code, error_msg)
    
    def send_error_on_socket(self, sock, client_addr, error_code, error_msg):
        """Send ERROR packet on specified socket"""
        error_packet = struct.pack('!HH', OP_ERROR, error_code)
        error_packet += error_msg.encode('ascii')[:507] + b'\x00'
        
        try:
            sock.sendto(error_packet, client_addr)
        except Exception as e:
            self.logger.error(f"Error sending error packet: {e}")

def create_default_config(filename):
    """Create a default configuration file"""
    config = configparser.ConfigParser()
    
    config['server'] = {
        'file': 'example.txt',
        'port': str(TFTP_PORT),
        'timeout': str(TIMEOUT),
        'retries': str(MAX_RETRIES),
        'log_level': 'INFO'
    }
    
    config['tftp'] = {
        'default_blksize': str(DEFAULT_BLOCK_SIZE),
        'max_blksize': str(MAX_BLOCK_SIZE),
        'allow_options': 'yes'
    }
    
    with open(filename, 'w') as f:
        config.write(f)
    
    print(f"Created default configuration file: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='Simple TFTP Server with options support'
    )
    parser.add_argument('filename', nargs='?', help='File to serve (overrides config)')
    parser.add_argument('-c', '--config', default='tftp_server.conf',
                        help='Configuration file (default: tftp_server.conf)')
    parser.add_argument('-p', '--port', type=int, help='Port to listen on (overrides config)')
    parser.add_argument('--create-config', action='store_true',
                        help='Create a default configuration file and exit')
    
    args = parser.parse_args()
    
    # Create default config if requested
    if args.create_config:
        create_default_config(args.config)
        sys.exit(0)
    
    # Load configuration
    config = configparser.ConfigParser()
    
    if os.path.exists(args.config):
        config.read(args.config)
    else:
        print(f"Configuration file '{args.config}' not found.")
        print(f"Run with --create-config to create a default configuration.")
        sys.exit(1)
    
    # Override config with command line arguments
    if args.filename:
        config['server']['file'] = args.filename
    if args.port:
        config['server']['port'] = str(args.port)
    
    # Validate configuration
    if 'server' not in config or 'file' not in config['server']:
        print("Error: No file specified in config or command line")
        sys.exit(1)
    
    # Check port privileges
    port = config.getint('server', 'port', fallback=TFTP_PORT)
    if port < 1024 and os.name != 'nt' and os.geteuid() != 0:
        print(f"Error: Port {port} requires root privileges on Unix-like systems")
        print("Try using a port >= 1024 or run with sudo")
        sys.exit(1)
    
    try:
        server = TFTPServer(config)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
