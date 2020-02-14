import socket
import ssl

sock = socket.socket()
sock.bind(('', 43433))
sock.listen(10)

while True:
    conn, addr = sock.accept()
    print(conn)
    data = conn.recv(1024)
    print(data)
