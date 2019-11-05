from http.server import BaseHTTPRequestHandler, HTTPServer
import http.server
import socketserver

PORT = 5003
Handler = http.server.SimpleHTTPRequestHandler
def run(IPv4_addr):
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        print("serving at port", PORT)
        httpd.handle_request()
        httpd.server_close()
        print("Shutdown initiated.")


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.path)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

if __name__ == '__main__':
    run('127.0.0.1')
