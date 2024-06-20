import json
import time
from mitmproxy import http, ctx
import os

class Logger:
    root = '/home/mitmproxy'
    ca_cert_path = f'{root}/mitmproxy-ca-cert.pem'

    def __init__(self):
        try:
            # export paths
            self.requests_file_path = f'{self.root}/requests.json'
            self.wss_messages_file_path = f'{self.root}/wss_messages.json'

            # load CA certificate content
            self.ca_cert_content = self.load_ca_cert_content()
            
            # init files if don't exist
            self.init_file(self.requests_file_path)
            self.init_file(self.wss_messages_file_path)
            
            # open files in read write
            self.requests_file = open(self.requests_file_path, 'r+')
            self.wss_messages_file = open(self.wss_messages_file_path, 'r+')
            
            # load existing data
            self.requests_data = json.load(self.requests_file)
            self.wss_messages_data = json.load(self.wss_messages_file)

        except Exception as e:
            ctx.log.info(f"[{self.timestamp_now()}] Error during Logger initialization: {e}")
    
    def timestamp_now(self):
     return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    
    # as ttn seems to provide cert to gateway
    # this fnct will load it, then will erase on-the-fly response
    def load_ca_cert_content(self):
        try:
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert_content = f.read()
                f.close()
            return ca_cert_content
        except Exception as e:
            timestamp = self.timestamp_now()
            ctx.log.info(f"[{timestamp}] Error loading CA certificate content: {e}")
            return b''

    def init_file(self, filepath):
        # init empty if don't exist
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump([], f)

    def append_to_file(self, file, data, data_list):
        data_list.append(data)
        file.seek(0)  # move to the beginning
        json.dump(data_list, file, indent=4)  # update json
        file.truncate()

    # handle http request
    def request(self, flow: http.HTTPFlow):
        content = flow.request.content
        # if json, do nothing, if not decode
        try:
            content = json.loads(content)
        except ValueError:
            content = flow.request.content.decode('utf-8', 'replace')


        timestamp = self.timestamp_now()

        if flow.websocket is None:
            request_info = {
                "timestamp": timestamp,
                "type": "http",
                "method": flow.request.method,
                "host": flow.request.host,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "content": content
            }

            # update file
            self.append_to_file(self.requests_file, request_info, self.requests_data)
            ctx.log.info(f"[{timestamp}] Logged HTTP request to {flow.request.host}")
        else:
            # Handle the WebSocket upgrade request
            ctx.log.info(f"[{timestamp}] WebSocket upgrade request to {flow.request.host}")

    # handle wss messages stream
    def websocket_message(self, flow: http.HTTPFlow):
        if flow.websocket is not None:
            timestamp = self.timestamp_now()
            message = flow.websocket.messages[-1]
            try:
                content = json.loads(message.content)
            except json.JSONDecodeError:
                content = message.content.decode('utf-8', 'replace')

            # mess to add
            message_info = {
                "timestamp": timestamp,
                "type": "websocket",
                "direction": "sent" if message.from_client else "received",
                "content": content
            }

            # update file
            self.append_to_file(self.wss_messages_file, message_info, self.wss_messages_data)

            ctx.log.info(f"[{timestamp}] Logged WebSocket message from {'client' if message.from_client else 'server'}")

    # remove root certif if present in https response
    def response(self, flow: http.HTTPFlow):
        timestamp = self.timestamp_now()
        try:
            if 'content-type' in flow.response.headers:
                if flow.response.headers['content-type'] == 'application/octet-stream':
                    if b'ISRG Root X10' in flow.response.content:
                        flow.response.content = self.ca_cert_content
                        ctx.log.info(f"[{self.timestamp_now()}] ISRG Root X10 intercepted and erased")
        except Exception as e:
            ctx.log.info(f"[{timestamp}] Error processing HTTP response: {e}")

    # on obj destruct kill the filestream
    def __del__(self):
        self.requests_file.close()
        self.wss_messages_file.close()

# add the current logger as new addon on mitmproxy
addons = [Logger()]