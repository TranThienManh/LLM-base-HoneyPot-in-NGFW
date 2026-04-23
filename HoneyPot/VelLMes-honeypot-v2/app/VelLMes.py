#!/usr/bin/env python3

import os
import sys
import argparse
import threading
import time
import logging
from datetime import datetime

# Import server modules
from ssh_server import SSHHoneypot
from http_server import HTTPHoneypot  
from mysql_server import MySQLHoneypot

class VelLMesManager:
    def __init__(self):
        self.setup_logging()
        self.services = {}
        
    def setup_logging(self):
        """Setup main logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('/app/Logs/vellmes_main.log')
            ]
        )
        self.logger = logging.getLogger('VelLMes-Main')
        
    def start_service(self, service_name):
        """Start individual service"""
        try:
            if service_name.lower() == 'ssh':
                service = SSHHoneypot()
                self.services['ssh'] = service
                thread = threading.Thread(target=service.start, name='SSH-Thread')
                thread.daemon = True
                thread.start()
                self.logger.info("SSH Honeypot started")
                
            elif service_name.lower() == 'http':
                service = HTTPHoneypot()
                self.services['http'] = service
                thread = threading.Thread(target=service.start, name='HTTP-Thread')
                thread.daemon = True
                thread.start()
                self.logger.info("HTTP Honeypot started")
                
            elif service_name.lower() == 'mysql':
                service = MySQLHoneypot()
                self.services['mysql'] = service  
                thread = threading.Thread(target=service.start, name='MySQL-Thread')
                thread.daemon = True
                thread.start()
                self.logger.info("MySQL Honeypot started")
                
            else:
                self.logger.error(f"Unknown service: {service_name}")
                
        except Exception as e:
            self.logger.error(f"Failed to start {service_name}: {e}")
            
    def start_all_services(self):
        """Start all honeypot services"""
        self.logger.info("Starting VelLMes Honeypot System v2")
        
        services = ['ssh', 'http', 'mysql']
        for service in services:
            self.start_service(service)
            time.sleep(2)  # Delay between service starts
            
        self.logger.info("All services started successfully")
        
    def monitor_services(self):
        """Monitor service health"""
        while True:
            try:
                active_threads = threading.active_count()
                self.logger.info(f"Active threads: {active_threads}")
                
                for name, service in self.services.items():
                    if hasattr(service, 'stats'):
                        self.logger.info(f"{name.upper()} stats: {service.stats}")
                        
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
                
            time.sleep(300)  # Monitor every 5 minutes
            
    def run(self, services=None):
        """Main run method"""
        try:
            if services:
                for service in services:
                    self.start_service(service)
            else:
                self.start_all_services()
                
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_services, name='Monitor-Thread')
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Keep main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("VelLMes shutting down...")
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"VelLMes error: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='VelLMes Honeypot System v2')
    parser.add_argument('--services', nargs='+', choices=['ssh', 'http', 'mysql'], 
                       help='Specific services to run')
    parser.add_argument('--config-dir', default='/app/configs', 
                       help='Configuration directory')
    
    args = parser.parse_args()
    
    # Create directories if they don't exist
    os.makedirs('/app/Logs/SSH', exist_ok=True)
    os.makedirs('/app/Logs/HTTP', exist_ok=True)
    os.makedirs('/app/Logs/MySQL', exist_ok=True)
    os.makedirs('/app/Conversations/SSH', exist_ok=True)
    os.makedirs('/app/Conversations/HTTP', exist_ok=True)
    os.makedirs('/app/Conversations/MySQL', exist_ok=True)
    
    # Start VelLMes
    vellmes = VelLMesManager()
    vellmes.run(args.services)

if __name__ == "__main__":
    main()