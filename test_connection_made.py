import asyncio
asyncio.tasks._DEBUG = True
import socket
from socket import AF_INET
import ssl

class EchoServer(asyncio.Protocol):
    def connection_made(self, transport):
        name = transport.get_extra_info('sockname')
        peername = transport.get_extra_info('peername')
        print('Connection:',name,'<--',peername)
        self.transport = transport

    # This is where the magic happens
    # async def send_data(self, data):
    #         print("Making connection")
    #         reader, writer = await asyncio.open_connection('127.0.0.1', 8889)
    #         print("Connection made")
    #         writer.write(data)
    #         print("Data sent")
    #         # For some reason, not providing n caused this to not return anything
    #         resp = await reader.read(1024)
    #         print("Got response")
    #         self.transport.write(resp)
    #         print('Data returned:',resp)

async def main():
    coro_1 = await asyncio.open_connection(host='192.168.88.18', port=443, family=AF_INET,
                                             ssl=ssl.SSLContext(ssl.PROTOCOL_TLS))

# loop = asyncio.get_event_loop()
loop = asyncio.new_event_loop()
#coro_1 = loop.create_connection(EchoServer, host='192.168.88.18', port=443, family=AF_INET, ssl=ssl.SSLContext(ssl.PROTOCOL_TLS))

# server_1 = loop.run_until_complete(coro_1)
asyncio.run(main())
# server_1 = loop.run_until_complete(task)
print (dir(server_1[1]))
sock = server_1[0].get_extra_info('socket').getpeername()
print (type(sock))
# sock.getaddrinfo()
print('Serving on {}'.format(sock))
# print(sock.family)
# print(sock.getpeername())
# print(sock.type)
# print(sock.proto)

try:
    loop.run_forever()
except KeyboardInterrupt:
    print("^C caught, exiting")
finally:
    server_1.close()
    loop.close()