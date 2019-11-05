import http.server
import socketserver

PORT = 5002
Handler = http.server.SimpleHTTPRequestHandler
def run(IPv4_addr):
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()

if __name__ == '__main__':
    run('127.0.0.1')