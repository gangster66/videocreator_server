import socket
import ssl

sock = ssl.wrap_socket(socket.socket(), 'keys/private.key', 'keys/server.crt', True)
sock.bind( ('localhost', 43433) )
sock.listen(10)

while True:
    conn, addr = sock.accept()
    data = conn.recv(1024)
    print(data)
