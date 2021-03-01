import http.server
import socketserver
import time

PORT = 5002
Handler = http.server.SimpleHTTPRequestHandler
def run(IPv4_addr):
    try:
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            print("HTTP Server serving at port", PORT)
            httpd.serve_forever()
    except OSError:
        print('Port 5002 blocked')
        time.sleep(1)
        run(IPv4_addr)

if __name__ == '__main__':
    run('127.0.0.1')