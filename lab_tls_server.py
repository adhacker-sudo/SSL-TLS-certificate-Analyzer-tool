import http.server
import ssl

server_address = ("127.0.0.1", 8443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="certcheck_lab_server.crt",
    keyfile="certcheck_lab_server.key",
)

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
print("Lab TLS server running on https://127.0.0.1:8443 ...")
httpd.serve_forever()