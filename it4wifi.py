import asyncio
import ssl
import hashlib
import base64
import re
import time
import xmltodict
from asyncio.streams import StreamWriter
import random
from socket import AF_INET
import queue


class it4wifi(asyncio.Protocol):
    def __init__(self, host_ip='localhost', username='python', host_mac='', source_name='test', source_description='IT4WiFi module', token=''):
        self.host_ip = host_ip
        self.host_mac = host_mac
        self.source_name = source_name
        self.source_description = source_description
        self.username = username
        self.token = token
        self.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        # Client challenge, randomly generated
        self.client_challenge = '{:08x}'.format(random.randint(1, 9999999)).upper()
        # Server challenge, send by server
        self.server_challenge = ""
        self.command_sequence = 1
        self.command_id = 0
        # TODO: Increment session_id when reconnect accessory
        self.session_id = 1
        self._reader = asyncio.StreamReader
        self._writer = asyncio.StreamWriter
        self.response = ''
        self._connected = False
        self.cmd_queue = asyncio.Queue()
        self.msg_queue = asyncio.Queue()
        self.new_msg_event = asyncio.Event()

    # Translate hex string to byte array
    def hex_str_to_byte_array(self, hexstring):
        return bytes.fromhex(hexstring)

    # Get sha256
    def mysha256(self, *args):
        m = hashlib.sha256()
        for a in args:
            m.update(a)
        return m.digest()

    # Invert byte array
    def invert_array(self, data):
        return data[::-1]

    # Generating command ID from session ID
    def generate_cmd_id(self, session_id):
        self.command_sequence += 1
        return (self.command_sequence << 8) | (int(session_id) & 255)

    # Find server challenge in response, needed fo message signature
    def find_server_challenge(self, msg):
        _match = re.search(r'sc=[\'"]?([^\'" >]+)', msg)
        if _match:
            self.server_challenge = _match.group(1)
            print(self.server_challenge)
        else:
            # TODO: need raise exception
            exit()

    # Check if sign needed
    def __is_sign_needed(self, cmd_type):
        if cmd_type == 'VERIFY' or cmd_type == 'CONNECT' or cmd_type == 'PAIR':
            return False
        else:
            return True

    # Build sign for message
    def build_sign(self, xml_command):
        client_challenge_arr = self.hex_str_to_byte_array(self.client_challenge)
        server_challenge_arr = self.hex_str_to_byte_array(self.server_challenge)

        pairing_pwd = base64.b64decode(self.token)
        session_pwd = self.mysha256(pairing_pwd, self.invert_array(server_challenge_arr),
                                    self.invert_array(client_challenge_arr))

        msg_hash = self.mysha256(xml_command.encode())
        sign = self.mysha256(msg_hash, session_pwd)
        return '<Sign>' + base64.b64encode(sign).decode("utf-8") + '</Sign>'

    async def open_connection(self):
        # TODO: Delete print()
        print('open connection')
        self._reader, self._writer = await asyncio.open_connection(host=self.host_ip, port=443,
                                                                   family=AF_INET, ssl=self.ssl_ctx)
        print('after connection')

    async def auth(self):
        await self.send_message('VERIFY', '<User username="{}"/>'.format(self.username))
        # TODO: Получение ответа от коробки. if re.search(r'Authentication\sid=[\'"]?([^\'" >]+)', self.response):
        while self.response == '':
            await self.new_msg_event.wait()
        if re.search(r'Authentication\sid=[\'"]?([^\'" >]+)', self.response):
            self.response = ''
            self.new_msg_event.clear()
            await self.send_message('CONNECT',
                                    '<Authentication username="{}" cc="{}"/>'.format(self.username, self.client_challenge))
            await self.new_msg_event.wait()
            self.find_server_challenge(self.response)
            self.response = ''

    async def connect(self, loop):
        # TODO: need make 5 attempt to connect
        await self.open_connection()
        # Starting listener fo receiving messages from accessory
        future = asyncio.ensure_future(self.msg_listener())
        # Go to Verify and Connect with accessory
        await self.auth()

    async def send_message(self, command_type, command_body):
        self.command_id = self.generate_cmd_id(self.session_id)
        start_request = '\u0002' + '<Request id="{}" source="{}" target="{}" gw="gwID" protocolType="NHK" protocolVersion="1.0" ' \
                                   'type="{}">\r\n'.format(
            self.command_id, self.source_name, self.host_mac, command_type)
        end_request = '</Request>\r\n' + '\u0003'
        message = (start_request + command_body + (
            self.build_sign(start_request + command_body) if self.__is_sign_needed(command_type) else "") + end_request)
        print ('send msg', message)
        self._writer.write(message.encode())
        await self._writer.drain()

    async def msg_listener(self):
        buff_size = 512
        data = b''
        #TODO: while is_connected
        print('Enter listener')
        while self._reader._transport != None and not self._reader._transport._closed and not self._reader._paused:
            if await self._reader.read(1) == b'\x02':
                inside_frame = True
                b_size = len(self._reader._buffer)
                for i in range (0, b_size, 1):
                    chunk = await self._reader.read(1)
                    if inside_frame and chunk == b'\x03':
                        inside_frame = False
                    if inside_frame:
                        data = data + chunk
                    else:
                        print('data is:', data.decode())
                        self.new_msg_event.set()
                        self.response = data.decode()
                        data = b''

    # TODO: Вся эта ботва работает в случае loop.create_connection
    def connection_made(self, transport):
        self.transport = transport
        self.address = transport.get_extra_info('peername')
        print(
            'connecting to {} port {}'.format(*self.address)
        )

    def disconnect(self) -> None:
        pass


async def main():
    t = start_time = time.time()

    print('Start main at', time.strftime('%H:%M:%S', time.localtime(start_time)))

    # async def waiter(event):
    #     print('waiting for it ...')
    #     await event.wait()
    #     print('... got it!')
    #
    # async def main():
    #     # Create an Event object.
    #     event = asyncio.Event()
    #
    #     # Spawn a Task to wait until 'event' is set.
    #     waiter_task = asyncio.create_task(waiter(event))
    #
    #     # Sleep for 1 second and set the event.
    #     await asyncio.sleep(1)
    #     event.set()
    #
    #     # Wait until the waiter task is finished.
    #     await waiter_task
    #
    # asyncio.run(main())

    loop = asyncio.get_event_loop()
    # loop.set_debug(True)
    nice = it4wifi('192.168.88.18', 'Homeassistant', '00:0B:6C:48:C8:49')
    await asyncio.gather(
        nice.connect(loop),
    )
    print ('after nice.connect')
    print('Work time is', time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time)))
    while True: # nice._reader._transport._closed:
        #await asyncio.sleep(1)
        if time.time() - t >= 60:
            t=time.time()
            print('reader_transport_closed is', nice._reader._transport._closed)
            print('reader_transport_exception is', nice._reader._exception)
            print('reader_transport_paused is', nice._reader._paused)
            print(time.strftime('%H:%M:%S'), 'Working', time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time)))
            print()
    print('Connection lost at', time.strftime('%H:%M:%S'))
    print ('Work time is', time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time)))
    nice._writer.close()
    await nice._writer.wait_closed()

    # if kk is not None:
    #    print(kk.getpeername)
    # loop.stop()
    # loop.close()


if __name__ == '__main__':
    print('start in main mode')
    asyncio.run(main())
