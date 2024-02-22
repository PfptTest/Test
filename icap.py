import re......123
import time,,,dzfsdf
from xmlrpc.client import ServerProxy, Fault

from locust import HttpUser, task, between
from gevent import socket

DEBUG = False
SWG_PROXY_IP = ''  # put the IP of your ICAP server here
SWG_PROXY_PORT = 0  # put the port of your ICAP server here
REQUEST_PAYLOAD = (
    'GET https://www.google.com/ HTTP/1.1\r\n'
    'User-Agent: curl/7.68.0\r\n'
    'Accept: */*\r\n'
    'Host: www.google.com\r\n'
    '\r\n'
)
RESPONSE_HEADERS_PAYLOAD = (
    'HTTP/1.1 200 OK\r\n'
    'Date: Thu, 03 Nov 2022 15:18:36 GMT\r\n'
    'Expires: -1\r\n'
    'Cache-Control: private, max-age=0\r\n'
    'Content-Type: text/html; charset=ISO-8859-1\r\n'
    'P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."\r\n'
    'Server: gws\r\n'
    'X-XSS-Protection: 0\r\n'
    'X-Frame-Options: SAMEORIGIN\r\n'
    'Set-Cookie: AEC=AakniGNegtIqcE-qjXdjtIio7TuRlhiYtrrmbpAYrkxMspr0VkiHIz_gLY4; expires=Tue, 02-May-2023 15:18:36 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax\r\n'
    'Set-Cookie: __Secure-ENID=7.SE=rSrR9PXE7R1n8KMvzHzv7qnFIlTTjqWwCGTIbJtq8cK8LtLssX9Z5NHFdGqcAUsNCLxfxoA-lcSHeqdxvPfJT4F6IujVHhWL4aD5_m-l70M8o7mskFmdTpS15sMSafvF0Ugn9VEypnvkFf8b00ItCNdEvp1ULkfaVbAVGHyYwvY; expires=Mon, 04-Dec-2023 07:36:54 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax\r\n'
    'Set-Cookie: CONSENT=PENDING+883; expires=Sat, 02-Nov-2024 15:18:36 GMT; path=/; domain=.google.com; Secure\r\n'
    'Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"\r\n'
    'Accept-Ranges: none\r\n'
    'Vary: Accept-Encoding\r\n'
    '\r\n'
)
# RESPONSE_BODY_PAYLOAD = (
#     '5c\r\n'
#     'This is data that was returned by an origin server, but with\r\n'
#     'value added by an ICAP server.\r\n'
#     '0\r\n'
# )


class IcapResponse:
    def __init__(self):
        self.status_code = None
        self.status = None
        self.headers = {}

    def load(self, raw):
        lines = raw.splitlines()
        if not len(lines):
            print("empty ICAP response")
            return

        protocol, status_code, status = lines[0].split(' ')
        if protocol != 'ICAP/1.0':
            print("bad protocol token")
            return

        try:
            status_code = int(status_code)
        except ValueError:
            print("status code isn't numeric")
            return

        try:
            end_of_icap_header_index = lines.index('')
        except ValueError:
            print("no empty line between ICAP headers and encapsulated message")
            return

        self.status_code = status_code
        self.status = status
        for line in lines[1:end_of_icap_header_index]:
            key, value = line.split(': ')
            self.headers[key] = value

        return self


class IcapUser(HttpUser):
    # wait_time = between(1, 1)

    def __init__(self, environment):
        super().__init__(environment)
        self._request_event = environment.events.request
        self.req_sock = None
        self.resp_sock = None

    @staticmethod
    def measure(request_meta=None):
        if request_meta:
            request_meta['response_time'] = \
                (time.perf_counter() - request_meta['measure_start']) * 1000
            request_meta.pop('measure_start')
            return request_meta

        return {
            "request_type": "icap",
            "name": "koko",
            "start_time": time.time(),
            "response_length": 0,
            "response": None,
            "context": {},
            "exception": None,
            "measure_start": time.perf_counter()
        }

    def create_new_connected_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SWG_PROXY_IP, SWG_PROXY_PORT))

        return s

    def create_new_connected_req_socket(self):
        if self.req_sock:
            self.req_sock.close()

        self.req_sock = self.create_new_connected_socket()

    def create_new_connected_resp_socket(self):
        if self.resp_sock:
            self.resp_sock.close()

        self.resp_sock = self.create_new_connected_socket()

    def send_icap_request(self, sock, req):
        sent = 0
        req = req.encode()
        try:
            sent = sock.send(req)
        except Exception as e:
            print(e)

        return sent > 0

    def recv_icap_response(self, sock):
        chunks = []
        end_seen = False
        while not end_seen:
            chunk = sock.recv(2048).decode()
            if chunk == '':
                return None
            chunks.append(chunk)
            if '\r\n\r' in chunk:
                end_seen = True

        return '\n'.join(chunks)

    @task
    def reqmod(self):
        if not self.req_sock:
            self.create_new_connected_req_socket()

        req = ('REQMOD icap://localhost/request ICAP/1.0\r\n'
               'Host: localhost\r\n'
               'User-Agent: C-ICAP-Client-Library/0.01\r\n'
               'Allow: 204\r\n'
               'Encapsulated: req-hdr=0, null-body=%s\r\n'
               'X-PMeta-OID: org-1\r\n'
               'X-PMeta-UID: usr-ErUn6eR6dwnlz\r\n'
               'X-PMeta-Src-Ext-IP: 18.192.244.223\r\n'
               '\r\n')

        data = req % len(REQUEST_PAYLOAD) + REQUEST_PAYLOAD
        if DEBUG:
            print("ICAP request:")
            print(data)

        request_meta = self.measure()
        success = self.send_icap_request(self.req_sock, data)
        if not success:
            print("Failed to send ICAP request")
            self.req_sock.close()
            self.req_sock = None
            return

        raw_resp = self.recv_icap_response(self.req_sock)
        if not raw_resp:
            print("Failed to recv ICAP response")
            self.req_sock.close()
            self.req_sock = None

        icap_response = IcapResponse().load(raw_resp)

        if icap_response.status_code != 204:
            print('unexpected ICAP response: %s' % icap_response.status_code)
        if icap_response.headers.get('Connection') == 'close':
            if DEBUG:
                print("close socket")
            self.create_new_connected_req_socket()

        request_meta = self.measure(request_meta)
        self._request_event.fire(**request_meta)

    # @task
    def respmod(self):
        if not self.resp_sock:
            self.create_new_connected_resp_socket()

        req = ('RESPMOD icap://localhost/request ICAP/1.0\r\n'
               'Host: localhost\r\n'
               'User-Agent: C-ICAP-Client-Library/0.01\r\n'
               'Allow: 204\r\n'
               'Preview: 0\r\n'
               'Encapsulated: req-hdr=0, res-hdr=%s, res-body=%s\r\n'
               'X-PMeta-OID: org-1\r\n'
               'X-PMeta-UID: usr-ErUn6eR6dwnlz\r\n'
               'X-PMeta-Src-Ext-IP: 18.192.244.223\r\n'
               '\r\n') % (len(REQUEST_PAYLOAD),
                          len(REQUEST_PAYLOAD) + len(RESPONSE_HEADERS_PAYLOAD))
        
        data = req + REQUEST_PAYLOAD + RESPONSE_HEADERS_PAYLOAD
        if DEBUG:
            print("ICAP request:")
            print(data)

        request_meta = self.measure()
        success = self.send_icap_request(self.resp_sock, data)
        if not success:
            print("Failed to send ICAP request")
            self.resp_sock.close()
            self.resp_sock = None
            return

        raw_resp = self.recv_icap_response(self.resp_sock)
        if not raw_resp:
            print("Failed to recv ICAP response")
            self.resp_sock.close()
            self.resp_sock = None

        icap_response = IcapResponse().load(raw_resp)

        if icap_response.status_code != 204:
            print('unexpected ICAP response: %s' % icap_response.status_code)
        if icap_response.headers.get('Connection') == 'close':
            if DEBUG:
                print("close socket")
            self.create_new_connected_resp_socket()

        request_meta = self.measure(request_meta)
        self._request_event.fire(**request_meta)
