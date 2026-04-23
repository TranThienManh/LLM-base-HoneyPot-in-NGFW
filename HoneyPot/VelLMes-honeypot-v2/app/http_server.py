import socket
import threading
import logging
import requests
import yaml
import os
import json
import re
import time
from datetime import datetime
from collections import defaultdict
import hashlib
import urllib.parse
import html
import random

class GroqClient:
    def __init__(self, api_key, model="llama3-70b-8192"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        
    def generate_response(self, prompt, max_tokens=2048, temperature=0.8):
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
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()
            raw_response = result['choices'][0]['message']['content'].strip()
            # Remove any explanatory text before the HTTP response
            if not raw_response.startswith('HTTP/'):
                lines = raw_response.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('HTTP/'):
                        return '\n'.join(lines[i:])
            return raw_response
        except Exception as e:
            logging.error(f"Groq API error: {e}")
            return self.get_fallback_response()
            
    def get_fallback_response(self):
        body = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Internal Server Error</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Internal Server Error</h1>
    <p>The server encountered an error.</p>
</body>
</html>"""
        return f"""HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=UTF-8
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Length: {len(body.encode())}
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body}"""

class HTTPHoneypot:
    def __init__(self, config_file='/app/configs/configHTTP.yml'):
        self.load_config(config_file)
        self.setup_logging()
        self.groq = GroqClient(
            api_key=os.getenv('GROQ_API_KEY'),
            model=os.getenv('MODEL', 'llama3-70b-8192')
        )
        self.stats = {'requests': 0, 'attacks': 0, 'blocked_ips': 0}
        self.rate_limit_tracker = defaultdict(list)
        self.blocked_ips = set()
        self.session_context = defaultdict(dict)
        
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
        
        self.logger = logging.getLogger('HTTP-Honeypot')
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(self.config['logging']['level'])
        
    def log_conversation(self, data, addr, method, path, headers, body):
        conv_file = self.config['logging']['conversation_file']
        os.makedirs(os.path.dirname(conv_file), exist_ok=True)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": addr[0],
            "client_port": addr[1],
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "response": data
        }
        
        with open(conv_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
            
    def parse_request(self, request_data):
        try:
            lines = request_data.decode('utf-8', errors='ignore').split('\r\n')
            if not lines:
                return None, None, {}, ""
                
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None, None, {}, ""
                
            method = parts[0]
            path = parts[1]
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ""
            return method, path, headers, body
        except Exception as e:
            self.logger.error(f"Error parsing HTTP request: {e}")
            return None, None, {}, ""
            
    def is_suspicious_request(self, method, path, headers, body):
        check_string = f"{method} {path} {str(headers)} {body}".lower()
        
        for pattern in self.config['attack_detection']['suspicious_patterns']:
            if re.search(pattern, check_string, re.IGNORECASE):
                return True
                
        user_agent = headers.get('User-Agent', '').lower()
        if any(tool in user_agent for tool in ['nikto', 'sqlmap', 'burp']):
            return True
            
        return False
        
    def check_rate_limit(self, client_ip):
        current_time = time.time()
        self.rate_limit_tracker[client_ip] = [
            t for t in self.rate_limit_tracker[client_ip]
            if current_time - t < 60
        ]
        
        self.rate_limit_tracker[client_ip].append(current_time)
        
        if len(self.rate_limit_tracker[client_ip]) > self.config['attack_detection']['rate_limit']['requests_per_minute']:
            self.blocked_ips.add(client_ip)
            self.stats['blocked_ips'] += 1
            self.logger.warning(f"IP {client_ip} blocked due to rate limiting")
            time.sleep(self.config['attack_detection']['rate_limit']['block_duration'])
            self.blocked_ips.remove(client_ip)
            return True
        return False
        
    def generate_session_id(self):
        return hashlib.md5(str(time.time()).encode()).hexdigest()
        
    def handle_connection(self, client_socket, addr):
        self.stats['requests'] += 1
        self.logger.info(f"HTTP connection from {addr[0]}:{addr[1]}")
        
        try:
            if addr[0] in self.blocked_ips:
                response = self.get_blocked_response()
                client_socket.send(response.encode())
                return
                
            if self.check_rate_limit(addr[0]):
                response = self.get_blocked_response()
                client_socket.send(response.encode())
                return
                
            request_data = client_socket.recv(4096)
            if not request_data:
                return
                
            method, path, headers, body = self.parse_request(request_data)
            if not method:
                return
                
            self.logger.info(f"HTTP request from {addr[0]}: {method} {path}")
            
            client_ip = addr[0]
            self.session_context[client_ip]['last_path'] = path
            self.session_context[client_ip]['last_method'] = method
            self.session_context[client_ip].setdefault('session_id', self.generate_session_id())
            
            is_suspicious = self.is_suspicious_request(method, path, headers, body)
            if is_suspicious:
                self.stats['attacks'] += 1
                self.logger.warning(f"Suspicious HTTP request from {addr[0]}: {method} {path}")
                self.log_conversation(f"SUSPICIOUS: {method} {path}", addr, method, path, headers, body)
            
            time.sleep(self.config['server']['response_delay'] if path in ['/admin', '/wp-admin', '/login', '/wp-login.php'] else 0.1)
            
            if path == '/health':
                body = json.dumps({"status": "healthy", "requests": self.stats['requests'], "attacks": self.stats['attacks']})
                response = f"""HTTP/1.1 200 OK
Content-Type: application/json
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Length: {len(body.encode())}
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body}"""
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            if method not in ['GET', 'POST', 'HEAD']:
                response = self.get_method_not_allowed_response(client_ip)
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            if method == 'HEAD':
                response = self.get_head_response(client_ip)
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            if (method == 'POST' and path in ['/wp-login.php', '/admin', '/login']) or (method == 'GET' and path in ['/wp-admin', '/admin', '/login']):
                response = self.handle_login_attempt(method, path, headers, body, client_ip)
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            if path.startswith('/search') or path.startswith('/query'):
                response = self.handle_search(method, path, headers, body, client_ip)
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            if path.startswith(('/wp-json', '/api', '/rest')):
                response = self.handle_api_request(method, path, headers, body, client_ip)
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            if path.startswith(('/wp-content/plugins', '/modules')):
                response = self.handle_plugin_request(method, path, headers, body, client_ip)
                client_socket.send(response.encode())
                self.log_conversation(response, addr, method, path, headers, body)
                return
                
            context = self.session_context[client_ip]
            full_prompt = f"""{self.config['personality_prompt']}

Session Context:
Last Path: {context.get('last_path', '')}
Last Method: {context.get('last_method', '')}
Session ID: {context.get('session_id', '')}

HTTP Request Details:
Method: {method}
Path: {path}
Headers: {headers}
Body: {body}

Generate a complete HTTP response with headers and realistic content (HTML, JSON, XML, or plain text) based on the request. Ensure the response mimics a vulnerable web server, varying server type and framework as appropriate."""
            
            response = self.groq.generate_response(
                full_prompt,
                max_tokens=self.config['llm']['max_tokens'],
                temperature=self.config['llm']['temperature']
            )
            
            if not response.startswith('HTTP/'):
                server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
                server = random.choice(server_types)
                session_names = ["wordpress_session", "session_id"]
                session_name = random.choice(session_names)
                content_types = ["text/html; charset=UTF-8", "application/json", "text/plain"]
                content_type = random.choice(content_types) if not path.startswith(('/api', '/rest')) else "application/json"
                if content_type == "application/json":
                    body = json.dumps({"error": f"Invalid endpoint: {path}"})
                    status = "200 OK"
                elif content_type == "text/plain":
                    body = f"Error: Resource not found at {path}"
                    status = "404 Not Found"
                else:
                    body = response if response else f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Welcome to Site</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Welcome to Site</h1>
    <p>This is a {random.choice(['WordPress', 'Joomla', 'custom'])} application.</p>
</body>
</html>"""
                    status = "200 OK" if response else random.choice(["200 OK", "404 Not Found"])
                response = f"""HTTP/1.1 {status}
Content-Type: {content_type}
Server: {server}
X-Powered-By: PHP/7.4.3
Content-Length: {len(body.encode())}
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body}"""
            
            client_socket.send(response.encode())
            self.log_conversation(response, addr, method, path, headers, body)
            
        except Exception as e:
            self.logger.error(f"HTTP connection error: {e}")
            response = self.get_fallback_response()
            try:
                client_socket.send(response.encode())
            except:
                pass
        finally:
            client_socket.close()
            
    def handle_login_attempt(self, method, path, headers, body, client_ip):
        self.logger.info(f"Login attempt on {path} from {client_ip}")
        context = self.session_context[client_ip]
        frameworks = ["WordPress", "Joomla", "Generic Admin"]
        framework = random.choice(frameworks)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Log In ‹ {framework} Dashboard</title>
    <link rel="stylesheet" href="/css/{framework.lower()}/admin.css">
</head>
<body class="login">
    <div id="login">
        <h1>{framework}</h1>
        <form name="loginform" action="{path}" method="post">
            <p>
                <label for="user_login">Username<br />
                <input type="text" name="log" id="user_login" class="input" value="" size="20" /></label>
            </p>
            <p>
                <label for="user_pass">Password<br />
                <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label>
            </p>
            <p class="submit">
                <input type="submit" name="wp-submit" class="button button-primary" value="Log In" />
            </p>
        </form>
        <p id="nav">
            <a href="{path}?action=lostpassword">Lost your password?</a>
        </p>
    </div>
</body>
</html>"""
        if method == 'POST':
            body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Login Error</title>
    <link rel="stylesheet" href="/css/{framework.lower()}/admin.css">
</head>
<body class="login">
    <div id="login">
        <h1>Login Error</h1>
        <p>Invalid Username or Password</p>
        <p><a href="{path}">Back to login</a></p>
    </div>
</body>
</html>"""
        return f"""HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: {random.choice(['Apache/2.4.41 (Ubuntu)', 'Nginx/1.18.0'])}
X-Powered-By: PHP/7.4.3
Content-Length: {len(body_content.encode())}
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body_content}"""
            
    def handle_search(self, method, path, headers, body, client_ip):
        self.logger.info(f"Search request on {path} from {client_ip}")
        context = self.session_context[client_ip]
        parsed_url = urllib.parse.urlparse(path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query = query_params.get('q', [''])[0]
        sanitized_query = html.escape(query)
        server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
        server = random.choice(server_types)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        fake_results = [
            ["Post 1: News Update", "Post 2: Tech Tips"],
            ["Article: Welcome", "Blog: Site News"],
            []
        ][int(time.time()) % 3]
        body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Search Results</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body class="search">
    <h1>Search Results for: {sanitized_query}</h1>
    <ul>
        {"".join(f'<li>{result}</li>' for result in fake_results) or '<p>No results found for your query.</p>'}
    </ul>
</body>
</html>"""
        if 'select' in sanitized_query.lower() and 'from' in sanitized_query.lower():
            fake_table = ["users", "posts", "comments"][int(time.time()) % 3]
            body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Search Results</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body class="search">
    <h1>Search Results for: {sanitized_query}</h1>
    <p>Error: You have an error in your SQL syntax; check the manual for table '{fake_table}'.</p>
</body>
</html>"""
        elif '../' in sanitized_query or '/etc/' in sanitized_query:
            fake_files = [
                ["config.bak", "site.conf", "db.dump"],
                ["settings.conf", "backup.sql", "logs.txt"],
                ["wp-backup.sql", "config-old.bak", "archive.zip"]
            ][int(time.time()) % 3]
            body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Directory Listing</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Directory Listing</h1>
    <ul>
        {"".join(f'<li><a href="/files/{f}">{f}</a></li>' for f in fake_files)}
    </ul>
</body>
</html>"""
        return f"""HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: {server}
X-Powered-By: PHP/7.4.3
Content-Length: {len(body_content.encode())}
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body_content}"""
            
    def handle_plugin_request(self, method, path, headers, body, client_ip):
        self.logger.info(f"Plugin request on {path} from {client_ip}")
        context = self.session_context[client_ip]
        server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
        server = random.choice(server_types)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        plugins = [
            {"name": "contact-form-7", "version": f"v5.{int(time.time()) % 10}.0"},
            {"name": "yoast-seo", "version": f"v16.{int(time.time()) % 5}.1"},
            {"name": "akismet", "version": f"v4.{int(time.time()) % 3}.5"}
        ]
        plugin_name = path.split('/')[3] if len(path.split('/')) > 3 else ""
        if plugin_name in [p["name"] for p in plugins]:
            plugin = next(p for p in plugins if p["name"] == plugin_name)
            body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>Plugin: {plugin['name']}</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Plugin: {plugin['name']}</h1>
    <p>Version: {plugin['version']}</p>
    <p>This is an active plugin/module.</p>
</body>
</html>"""
            status = "200 OK"
        else:
            body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>404 Not Found</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL {path} was not found on this server.</p>
</body>
</html>"""
            status = "404 Not Found"
        return f"""HTTP/1.1 {status}
Content-Type: text/html; charset=UTF-8
Server: {server}
X-Powered-By: PHP/7.4.3
Content-Length: {len(body_content.encode())}
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body_content}"""
            
    def handle_api_request(self, method, path, headers, body, client_ip):
        self.logger.info(f"API request on {path} from {client_ip}")
        context = self.session_context[client_ip]
        server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
        server = random.choice(server_types)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        api_errors = [
            {"error": f"Invalid endpoint: {path}"},
            {"error": "API version not supported"},
            {"error": "Authentication required"}
        ]
        if path.startswith('/wp-json'):
            body_content = json.dumps(random.choice(api_errors))
            content_type = "application/json"
            status = "200 OK"
        elif path == '/xmlrpc.php':
            body_content = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
    <fault>
        <value>
            <struct>
                <member>
                    <name>faultCode</name>
                    <value><int>405</int></value>
                </member>
                <member>
                    <name>faultString</name>
                    <value><string>XML-RPC services are disabled on this site.</string></value>
                </member>
            </struct>
        </value>
    </fault>
</methodResponse>"""
            content_type = "text/xml"
            status = "200 OK"
        else:
            body_content = json.dumps(random.choice(api_errors))
            content_type = "application/json"
            status = "200 OK"
        return f"""HTTP/1.1 {status}
Content-Type: {content_type}
Server: {server}
X-Powered-By: PHP/7.4.3
Content-Length: {len(body_content.encode())}
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body_content}"""
            
    def get_method_not_allowed_response(self, client_ip):
        context = self.session_context[client_ip]
        server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
        server = random.choice(server_types)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        error_messages = [
            "The method is not allowed for the requested URL.",
            "This HTTP method is not supported.",
            "Invalid request method."
        ]
        body_content = f"""<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>405 Method Not Allowed</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>405 Method Not Allowed</h1>
    <p>{random.choice(error_messages)}</p>
</body>
</html>"""
        return f"""HTTP/1.1 405 Method Not Allowed
Content-Type: text/html; charset=UTF-8
Server: {server}
X-Powered-By: PHP/7.4.3
Content-Length: {len(body_content.encode())}
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body_content}"""
            
    def get_head_response(self, client_ip):
        context = self.session_context[client_ip]
        server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
        server = random.choice(server_types)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        return f"""HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: {server}
X-Powered-By: PHP/7.4.3
Set-Cookie: {session_name}={context['session_id']}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close"""
            
    def get_blocked_response(self):
        server_types = ["Apache/2.4.41 (Ubuntu)", "Nginx/1.18.0"]
        server = random.choice(server_types)
        session_names = ["wordpress_session", "session_id"]
        session_name = random.choice(session_names)
        body_content = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title>429 Too Many Requests</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>429 Too Many Requests</h1>
    <p>Please try again later.</p>
</body>
</html>"""
        return f"""HTTP/1.1 429 Too Many Requests
Content-Type: text/html; charset=UTF-8
Server: {server}
Retry-After: {self.config['attack_detection']['rate_limit']['block_duration']}
Content-Length: {len(body_content.encode())}
Set-Cookie: {session_name}={random.choice(session_names)}={self.generate_session_id()}; Path=/; HttpOnly
Date: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Connection: close

{body_content}"""
            
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.config['server']['host'], self.config['server']['port']))
        server.listen(self.config['server']['max_connections'])
        
        self.logger.info(f"HTTP Honeypot listening on {self.config['server']['host']}:{self.config['server']['port']}")
        
        while True:
            try:
                client, addr = server.accept()
                client.settimeout(self.config['server']['timeout'])
                
                thread = threading.Thread(target=self.handle_connection, args=(client, addr))
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                self.logger.error(f"HTTP server error: {e}")

if __name__ == "__main__":
    honeypot = HTTPHoneypot()
    honeypot.start()