from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

def run(IPv4_addr):
    httpd = HTTPServer((IPv4_addr, 5001), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, certfile='web_cert.pem', keyfile='rsa_private_key.pem', server_side=True)
    print("Running!")
    httpd.serve_forever()

if __name__ == '__main__':
    run('127.0.0.1')