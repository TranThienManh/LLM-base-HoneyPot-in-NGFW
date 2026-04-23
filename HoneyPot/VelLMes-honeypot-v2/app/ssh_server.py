import socket
import paramiko
import threading
import time
import logging
import requests
import yaml
import os
from datetime import datetime
from paramiko import ServerInterface, Transport, RSAKey, Channel
from concurrent.futures import ThreadPoolExecutor

class GroqClient:
    def __init__(self, api_key, model="llama3-70b-8192"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    def generate_response(self, prompt, max_tokens=2048, temperature=0.2):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content'].strip()
                lines = [line.strip() for line in content.split('\n') if line.strip()]
                return '\n'.join(lines)
            else:
                logging.error(f"Groq API error: {response.status_code}")
                return "bash: command not found"
        except Exception as e:
            logging.error(f"Groq API exception: {e}")
            return "Connection timeout"

class SSHServer(ServerInterface):
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.session_id = None
        self.current_user = None

    def check_auth_password(self, username, password):
        if not self.session_id:
            self.session_id = f"{self.honeypot.current_addr[0]}_{int(time.time())}"
        self.honeypot.logger.info(f"Login attempt - IP: {self.honeypot.current_addr[0]}, User: {username}, Pass: {password}")
        self.honeypot.log_conversation(self.session_id, f"Login: {username}/{password}")
        if username in self.honeypot.users:
            self.current_user = username
            self.honeypot.current_users[self.session_id].append(username)
            self.honeypot.current_directories[self.session_id].append(f"/home/{username}" if username != "root" else "/root")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel: Channel, term: str, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes) -> bool:
        self.honeypot.logger.info(f"PTY request on channel {channel.get_id()} - Term: {term}, Size: {width}x{height}")
        return True

    def check_channel_shell_request(self, channel: Channel) -> bool:
        self.honeypot.logger.info(f"Shell request on channel {channel.get_id()}")
        return True

class SSHHoneypot:
    def __init__(self, config_file='/app/configs/configSSH.yml'):
        self.load_config(config_file)
        self.setup_logging()
        self.groq = GroqClient(
            api_key=os.getenv('GROQ_API_KEY'),
            model=os.getenv('MODEL', 'llama3-70b-8192')
        )
        self.users = ['root', 'admin', 'dev1', 'dev2', 'guest', 'backup_user']
        self.current_directories = {}  # Lưu trữ stack thư mục cho mỗi session
        self.current_users = {}  # Lưu trữ stack user cho mỗi session
        self.stats = {'connections': 0, 'commands': 0}
        self.current_addr = None

        key_path = '/app/Logs/SSH/host_key'
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        self.host_key = RSAKey.generate(2048)
        self.host_key.write_private_key_file(key_path)

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Failed to load config file {config_file}: {e}")
            raise

    def setup_logging(self):
        log_file = self.config['logging']['log_file']
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.logger = logging.getLogger('SSH-Honeypot')
        self.logger.handlers.clear()
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_conversation(self, session_id, data):
        conv_file = self.config['logging']['conversation_file']
        os.makedirs(os.path.dirname(conv_file), exist_ok=True)
        with open(conv_file, 'a') as f:
            f.write(f"[{datetime.now()}] Session {session_id}: {data}\n")

    def handle_connection(self, client: socket.socket, addr: tuple):
        session_id = f"{addr[0]}_{int(time.time())}"
        self.current_directories[session_id] = ["/home/admin"]  # Stack thư mục
        self.current_users[session_id] = ["admin"]  # Stack user
        self.stats['connections'] += 1
        self.current_addr = addr

        self.logger.info(f"SSH connection from {addr[0]}:{addr[1]} - Session: {session_id}")
        self.log_conversation(session_id, f"Connection established from {addr[0]}")

        try:
            transport = Transport(client)
            transport.add_server_key(self.host_key)
            server = SSHServer(self)
            server.session_id = session_id
            transport.start_server(server=server)
            channel = transport.accept(30)
            if channel is None:
                return

            if channel.active:
                channel.send(b"Welcome to Ubuntu 22.04.6 LTS (GNU/Linux 5.4.0-122-generic x86_64)\r\n")
                channel.send(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {addr[0]}\r\n".encode())

            while channel.active:
                current_user = self.current_users[session_id][-1]  # Lấy user mới nhất
                current_dir = self.current_directories[session_id][-1]  # Lấy thư mục mới nhất
                prompt = f"{current_user}@web-server-01:{current_dir}{'#' if current_user == 'root' else '$'} "
                channel.send(prompt.encode())

                command_buffer = ""
                while '\n' not in command_buffer and '\r' not in command_buffer:
                    data = channel.recv(1024).decode('utf-8', errors='ignore')
                    if not data:
                        return
                    command_buffer += data
                    channel.send(data.encode())  # Echo typed characters

                command = command_buffer.strip()
                channel.send(b"\r\n")  # Ensure command is fully displayed

                if not command or command.lower() in ['exit', 'logout', 'quit']:
                    if len(self.current_users[session_id]) > 1:  # Có user trước đó
                        self.current_users[session_id].pop()  # Xóa user hiện tại
                        self.current_directories[session_id].pop()  # Xóa thư mục hiện tại
                        channel.send(b"logout\r\n")
                        self.log_conversation(session_id, f"Command: {command}")
                        self.log_conversation(session_id, f"Response: Reverted to {self.current_users[session_id][-1]}")
                        continue
                    else:
                        channel.send(b"logout\r\n")
                        break

                self.stats['commands'] += 1
                self.logger.info(f"Command from {addr[0]} [{session_id}]: {command}")
                self.log_conversation(session_id, f"Command: {command}")

                # Xử lý lệnh SSH lồng nhau
                if command.startswith('ssh ') or command.startswith('ssh -p'):
                    parts = command.split()
                    target_user = None
                    target_host = None
                    for part in parts:
                        if '@' in part:
                            target_user, target_host = part.split('@', 1)
                            break
                    if target_user and target_host and target_user in self.users:
                        channel.send(f"{target_user}'s password: ".encode())
                        password_buffer = ""
                        while '\n' not in password_buffer and '\r' not in password_buffer:
                            data = channel.recv(1024).decode('utf-8', errors='ignore')
                            if not data:
                                return
                            password_buffer += data
                            channel.send(b"*")  # Echo ký tự mật khẩu giả
                        channel.send(b"\r\n")
                        self.current_users[session_id].append(target_user)
                        self.current_directories[session_id].append(f"/home/{target_user}" if target_user != "root" else "/root")
                        self.logger.info(f"Switched to user {target_user} in session {session_id}")
                        self.log_conversation(session_id, f"Switched to user: {target_user}")
                        channel.send(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {addr[0]}\r\n".encode())
                        response = ""
                    else:
                        response = "Connection closed."
                        self.log_conversation(session_id, f"Response: {response}")
                        channel.send((response + "\r\n").encode())
                        continue

                # Xử lý lệnh sudo su hoặc su
                elif command in ['sudo su', 'su']:
                    self.current_users[session_id].append("root")
                    self.current_directories[session_id].append("/root")
                    response = ""
                # Xử lý lệnh cd
                elif command.startswith('cd '):
                    new_dir = command.split(' ', 1)[1] or (f"/home/{current_user}" if current_user != "root" else "/root")
                    if new_dir == '~':
                        self.current_directories[session_id][-1] = f"/home/{current_user}" if current_user != "root" else "/root"
                    elif new_dir == '..':
                        parts = current_dir.rstrip('/').split('/')
                        self.current_directories[session_id][-1] = '/'.join(parts[:-1]) or '/'
                    elif new_dir.startswith('/'):
                        self.current_directories[session_id][-1] = new_dir
                    else:
                        self.current_directories[session_id][-1] = f"{current_dir}/{new_dir}".replace('//', '/')
                    response = ""
                # Xử lý các lệnh cơ bản cục bộ
                elif command == "whoami":
                    response = current_user
                elif command == "id":
                    uid = {"root": 0, "admin": 1000, "dev1": 1001, "dev2": 1002, "guest": 1003, "backup_user": 1004}.get(current_user, 1000)
                    groups = {
                        "root": "root",
                        "admin": "admin,developers",
                        "dev1": "developers",
                        "dev2": "developers",
                        "guest": "guests",
                        "backup_user": "backup"
                    }.get(current_user, "admin")
                    response = f"uid={uid}({current_user}) gid={uid}({groups}) groups={uid}({groups})"
                elif command == "groups":
                    response = {
                        "root": "root",
                        "admin": "admin developers",
                        "dev1": "developers",
                        "dev2": "developers",
                        "guest": "guests",
                        "backup_user": "backup"
                    }.get(current_user, "admin")
                elif command.startswith('ls') or command.startswith('dir'):
                    dir_contents = {
                        "/home/root": ["secret_key.txt", ".bashrc", ".bash_history"],
                        "/home/admin": ["Desktop", "Documents", ".ssh", "scripts", ".bash_history", ".bashrc"],
                        "/home/admin/Documents": ["passwords.txt", "notes.txt", "api_keys.yml"],
                        "/home/admin/.ssh": ["authorized_keys", "id_rsa", "known_hosts"],
                        "/home/admin/scripts": ["backup.sh"],
                        "/home/dev1": ["code", ".bash_history", ".bashrc"],
                        "/home/dev1/code": ["webapp", "scripts"],
                        "/home/dev1/code/webapp": ["app.py", "config.yml"],
                        "/home/dev1/code/scripts": ["deploy.sh"],
                        "/home/dev2": ["projects", ".bash_history", ".bashrc"],
                        "/home/dev2/projects": ["backend", "frontend"],
                        "/home/dev2/projects/backend": ["main.go"],
                        "/home/dev2/projects/frontend": ["index.js"],
                        "/home/guest": ["Downloads", ".bash_history", ".bashrc"],
                        "/home/backup_user": ["backups", ".bash_history", ".bashrc"],
                        "/home/backup_user/backups": ["db_backup.sql", "web_backup.tar.gz"],
                        "/var/www/html": ["index.html", "admin", "config.php", "uploads"],
                        "/var/www/html/admin": ["login.php"],
                        "/var/log": ["auth.log", "apache2", "nginx", "mysql"],
                        "/var/log/apache2": ["access.log", "error.log"],
                        "/var/log/nginx": ["access.log", "error.log"],
                        "/var/log/mysql": ["error.log", "slow.log"],
                        "/etc": ["passwd", "shadow", "group", "ssh", "apache2", "mysql"],
                        "/etc/ssh": ["sshd_config", "ssh_config"],
                        "/etc/apache2": ["apache2.conf", "sites-available"],
                        "/etc/apache2/sites-available": ["000-default.conf"],
                        "/etc/mysql": ["my.cnf"],
                    }
                    response = "\n".join(dir_contents.get(current_dir, []))
                elif command.startswith('cat '):
                    file_path = command.split(' ', 1)[1]
                    file_contents = {
                        "/etc/passwd": (
                            "root:x:0:0:root:/root:/bin/bash\n"
                            "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
                            "dev1:x:1001:1001:Developer 1:/home/dev1:/bin/bash\n"
                            "dev2:x:1002:1002:Developer 2:/home/dev2:/bin/bash\n"
                            "guest:x:1003:1003:Guest User:/home/guest:/bin/bash\n"
                            "backup_user:x:1004:1004:Backup User:/home/backup_user:/bin/bash"
                        ),
                        "/etc/group": (
                            "root:x:0:\n"
                            "admin:x:1000:admin\n"
                            "developers:x:1001:admin,dev1,dev2\n"
                            "guests:x:1002:guest\n"
                            "backup:x:1003:backup_user"
                        ),
                        "/home/admin/Documents/passwords.txt": (
                            "admin:admin123\n"
                            "dev1:devpass456\n"
                            "dev2:devpass789\n"
                            "mysql_root:dbpass321"
                        ),
                        "/home/admin/Documents/api_keys.yml": (
                            "aws:\n"
                            "  access_key: AKIAIOSFODNN7EXAMPLE\n"
                            "  secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                            "groq:\n"
                            "  api_key: gsk_1234567890abcdef"
                        ),
                        "/home/root/secret_key.txt": "SUPER_SECRET_KEY=abc123xyz789",
                        "/home/backup_user/backups/db_backup.sql": (
                            "-- MySQL dump 10.13  Distrib 8.0.28\n"
                            "CREATE DATABASE webapp;\n"
                            "USE webapp;\n"
                            "CREATE TABLE users (id INT, username VARCHAR(50));\n"
                            "INSERT INTO users VALUES (1, 'admin'), (2, 'dev1');"
                        ),
                    }
                    response = file_contents.get(file_path, f"cat: {file_path}: No such file or directory")
                else:
                    full_prompt = f"""{self.config['personality_prompt']}

Current directory: {current_dir}
Current user: {current_user}
Command executed: {command}

Provide only the command output, no explanations:"""
                    response = self.groq.generate_response(
                        full_prompt,
                        max_tokens=self.config['llm']['max_tokens'],
                        temperature=self.config['llm']['temperature']
                    )

                for line in response.splitlines():
                    channel.send(line.encode() + b'\r\n')
                    time.sleep(0.01)
                self.log_conversation(session_id, f"Response: {response}")

        except Exception as e:
            self.logger.error(f"SSH session error - {session_id}: {e}")
        finally:
            client.close()
            self.logger.info(f"SSH session ended - {session_id}")
            if session_id in self.current_directories:
                del self.current_directories[session_id]
            if session_id in self.current_users:
                del self.current_users[session_id]

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.config['server']['host'], self.config['server']['port']))
        server.listen(self.config['server']['max_connections'])
        self.logger.info(f"SSH Honeypot listening on {self.config['server']['host']}:{self.config['server']['port']}")

        with ThreadPoolExecutor(max_workers=self.config['server']['max_connections']) as executor:
            while True:
                try:
                    client, addr = server.accept()
                    executor.submit(self.handle_connection, client, addr)
                except Exception as e:
                    self.logger.error(f"SSH server error: {e}")
                    continue

if __name__ == "__main__":
    SSHHoneypot().start()