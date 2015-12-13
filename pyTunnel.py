import asyncio
import sys, traceback
from Crypto.Random.random import Random



__author__ = 'yunanw'

IS_SECURE = False
BUFFER_SIZE = 1024*8
REMOTE_SERVER_ADDR = None
PWD="yunanw"
block_size = 16

def print_exception(e):
    print("Exception in code:")
    print("-" * 60)
    print(e)
    print("-" * 60)
    traceback.print_exc(file=sys.stdout)
    print("-" * 60)


async def copy_to(src, dst):
    try:
        while True:
            data = await src.read(BUFFER_SIZE)
            if not data:
                print("copy_to: copy done")
                break

            await dst.write(data)
            await asyncio.sleep(0.01)
    except Exception as e:
        print_exception(e)


class Mixer:
    def __init__(self,iv):
        assert iv is not None
        self.iv = iv

    def mix(self,raw):

        data = b''
        for i in range(0, len(raw), block_size):
            rb = raw[i:i+block_size]
            or_code = self.iv[:len(rb)]
            b = bytes(x ^ y for x, y in zip(or_code,rb ))
            data += b

        return data


class Request:
    def __init__(self):
        self.version = None
        self.atyp = None
        self.cmd = None
        self.addr = None
        self.port = None

    def load(self, data):
        self.version = data[0]
        self.cmd = data[1]
        self.atyp = data[3]

        if self.atyp == 0x1:
            self.addr = data[4:7]
            self.port = int.from_bytes(data[8:], byteorder='big')
        elif self.atyp == 0x3:
            l = data[4]
            self.addr = (data[5:5 + l])
            self.port = int.from_bytes(data[5 + l:], byteorder='big')

        elif self.atyp == 0x4:
            self.addr = data[4:20]
            self.port = int.from_bytes(data[21:], byteorder='big')

    async def write_to(self, conn):

        if self.atyp == 3:
            res = b"\x05\x00\x00" \
                  + self.atyp.to_bytes(1, byteorder='big') \
                  + len(self.addr).to_bytes(1, byteorder='big') \
                  + self.addr \
                  + self.port.to_bytes(2, byteorder='big')
            await conn.write(res)


class Connection:
    def __init__(self, reader, writer, secure, iv= None):
        """

        """
        self._writer = writer
        self._reader = reader
        self.secure = secure
        self.iv = iv
        if self.iv is None:
            self.iv = Random.new().read(block_size)
        if self.secure and IS_SECURE:

            self.mixer = Mixer(self.iv)
            self.read = self.decrypt_wrapper(self.read)
            self.write = self.encrypt_warpper(self.write)

    def close(self):
        self._writer.close()

    async def read(self, size):

        d = await self._reader.read(size)
        return d

    async def write(self, data):
        self._writer.write(data)
        await self._writer.drain()

    def decrypt_wrapper(self,fn):
        async def wrapper(*args):
            data = await fn(*args)
            data = self.mixer.mix(data)
            return data
        return wrapper

    def encrypt_warpper(self,fn):
        async def wrapper(*args):
            data = self.mixer.mix(*args)
            await fn(data)

        return wrapper


class TunnelServerHandler:
    def __init__(self):

        self.client = None
        """:type client : Connection"""
        self.server = None
        """:type server_conn : Connection"""
        self._request = None
        """:type _request : Request"""

    async def _do_auth(self):
        data = await self.client.read(BUFFER_SIZE)
        print("auth header:", data)
        if data != b"\x05\x01\x00" and data != b"\x05\x01\x02":
            print("unsupportd version or methods!")
            self.client.close()
            return False

        await self.client.write(b"\x05\x00")
        return True

    async def _do_connect(self):
        try:
            server_reader, server_writer = await asyncio.open_connection(self._request.addr, self._request.port)
            await self._request.write_to(self.client)
            self.server = Connection(server_reader, server_writer, False)
            task = [copy_to(self.client, self.server), copy_to(self.server, self.client)]
            await asyncio.wait(task)
        except Exception as e:
            print_exception(e)

        finally:
            self.client.close()
            if self.server is not None:
                self.server.close()

    async def _process_request(self):

        data = await self.client.read(BUFFER_SIZE)
        print("request : ", data)
        self._request = Request()
        self._request.load(data)

        if self._request.version != 5:
            print("version is not 5\n")
            self.client.close()
            return

        if self._request.cmd == 1:
            await self._do_connect()
            return
        elif self._request.cmd == 2:
            print("unsupported command.%s \n", self._request.cmd)
            self.client.close()
            return
        elif self._request.cmd == 3:
            print("unsupported command.%s \n", self._request.cmd)
            self.client.close()
            return
        else:
            print("unsupported command.%s \n", self._request.cmd)
            self.client.close()
            return

    async def do_proxy(self):
        try:
            result = await self._do_auth()
            if result:
                await self._process_request()

        except Exception as e:
            print_exception(e)
        finally:
            try:
                if self.client is not None:
                    self.client.close()

                if self.server is not None:
                    self.server.close()
            except Exception as e:
                print_exception(e)

async def start_server(reader, writer):
    handler = TunnelServerHandler()
    iv = await reader.readexactly(block_size)
    handler.client = Connection(reader, writer, True,iv)
    print(handler.client.iv)
    await handler.do_proxy()

async def start_local(reader, writer):
    try:
        client = Connection(reader, writer, False)
        remote_reader, remote_writer = await asyncio.open_connection(REMOTE_SERVER_ADDR, 8817)
        server = Connection(remote_reader, remote_writer,True)
        server._writer.write(server.iv)
        print(server.iv)
        await server._writer.drain()
        task = [copy_to(client, server), copy_to(server, client)]
        await asyncio.wait(task)
    except Exception as e:
        print_exception(e)


def main(is_remote_server):

    fn = start_local
    port = 8325

    if is_remote_server:
        fn = start_server
        port = 8817

    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(fn, '0.0.0.0', port, loop=loop)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        main(True)
        print("Server Mode")
    else:
        print("Local Mode")
        REMOTE_SERVER_ADDR = sys.argv[1]
        main(False)
        print("Server Address", REMOTE_SERVER_ADDR)

