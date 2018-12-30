import socket
import struct

import base64
import hashlib
import threading


# noinspection PyBroadException
class WebSocketClient(threading.Thread):
    # 握手时需要的一个常量
    __GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    # 握手token在header中的key
    __HAND_SHAKE_HEADER_TOKEN = 'Sec-WebSocket-Key'
    # header中的结束标识符
    __HEADER_EOF = '\r\n\r\n'
    # header中的分割标识符
    __HEADER_SEP = '\r\n'

    # WebSocket的socket对象
    __conn = None
    # socket连接信息
    __conn_info = None
    # 全局唯一名称
    __name = None
    # 初始化连接对象
    __server = None

    # 是否已握手
    __handshaken = False

    # 长数据缓存
    __buffered = b''
    # 数据长度
    __message_length = 0

    def __init__(self, conn, conn_info, name, server):
        """
        初始化
        :param conn WebSocket的socket对象
        :param conn_info socket连接信息
        :param name 全局唯一名称
        :param server 初始化连接对象
        """
        super().__init__(name=name)

        self.__conn = conn
        self.__conn_info = conn_info
        self.__name = name
        self.__server = server

    def __log(self, msg):
        print(str(self.__conn_info) + '@' + self.__name + ': ' + msg)

    def get_conn(self):
        return self.__conn

    def generate_token(self, key):
        """ 生成握手鉴权key """
        return base64.b64encode(hashlib.sha1((key + self.__GUID).encode(encoding='utf-8')).digest()).decode('utf-8')

    def run(self):
        """ 启动客户端 """
        while True:
            # 已握手
            if self.__handshaken:
                try:
                    received_bytes = self.__conn.recv(2048)

                    # 空数据则断开连接
                    if len(received_bytes) == 0:
                        self.__server.disconnect_client(self.__name)
                        return

                    header_length = 6
                    if self.__message_length == 0:
                        # region 解析消息长度: 如果一次缓存没有接受完, 则循环多次后再一并处理
                        mask = received_bytes[1] & 127
                        if mask == 126:
                            mask = struct.unpack('>H', received_bytes[2:4])[0]
                            header_length = 8
                        elif mask == 127:
                            mask = struct.unpack('>Q', received_bytes[2:10])[0]
                            header_length = 14
                        self.__message_length = int(mask)
                        # endregion

                    self.__buffered += received_bytes

                    # 长数据时未接受完不处理业务
                    if len(self.__buffered) - header_length < self.__message_length:
                        continue

                    received_message = self.decode(self.__buffered)

                    self.__log('>>' + received_message)

                    # 触发回调
                    try:
                        for cb in self.__server.get_callbacks():
                            cb(self.__conn, received_message)
                    except BaseException as callback_e:
                        self.__log('触发回调失败: ' + callback_e)

                    self.__buffered = b''
                    self.__message_length = 0
                except BaseException as e:
                    self.__log('处理消息错误: ' + e)
                    self.__buffered = b''
                    self.__message_length = 0
            # 进行握手操作
            else:
                try:
                    # 获取发送的数据
                    received_data = self.__conn.recv(2048).decode('utf-8')
                    if received_data.find(self.__HEADER_EOF) == -1:
                        raise ValueError('握手数据错误')
                    # 分割数据来匹配web socket协议
                    headers = {}
                    for header in received_data.split(self.__HEADER_EOF)[0].split(self.__HEADER_SEP)[1:]:
                        key, value = header.split(':', 1)
                        headers[key] = value.strip()
                    if self.__HAND_SHAKE_HEADER_TOKEN not in headers:
                        raise ValueError('无' + self.__HAND_SHAKE_HEADER_TOKEN)

                    sec_websocket_key = headers[self.__HAND_SHAKE_HEADER_TOKEN]
                    response_key = self.generate_token(sec_websocket_key)

                    self.__conn.send(bytes('HTTP/1.1 101 Web Socket Protocol Handshake\r\n', encoding='utf8'))
                    self.__conn.send(bytes('Upgrade: websocket\r\n', encoding='utf8'))
                    self.__conn.send(bytes('Sec-WebSocket-Accept: ' + response_key + '\r\n', encoding='utf8'))
                    self.__conn.send(bytes('Connection: Upgrade\r\n', encoding='utf8'))
                    self.__conn.send(bytes('\r\n', encoding='utf8'))

                    self.__handshaken = True
                    self.__log(sec_websocket_key + ' -> ' + response_key + ': 握手完成')

                    # self.send('连接成功!')
                except BaseException as e:
                    self.__log('握手失败: ' + e)
                    self.__server.disconnect_client(self.__name)
                    return

    def send(self, message):
        """ 发送消息 """
        msg_len = len(message.encode())
        msg = b'\x81'

        if msg_len <= 125:
            msg += str.encode(chr(msg_len))
        elif msg_len <= 65535:
            msg += struct.pack('b', 126)
            msg += struct.pack('>h', msg_len)
        elif msg_len <= (2 ^ 64 - 1):
            msg += struct.pack('b', 127)
            msg += struct.pack('>q', msg_len)
        else:
            self.__log('消息过长: ' + message)
            return

        msg = msg + message.encode('utf-8')

        self.__conn.send(msg)
        self.__log('<<' + message)

    @staticmethod
    def decode(msg):
        """ 解析客户端发送的消息 """
        msg_len = msg[1] & 127
        if msg_len == 126:
            masks = msg[4:8]
            data = msg[8:]
        elif msg_len == 127:
            masks = msg[10:14]
            data = msg[14:]
        else:
            masks = msg[2:6]
            data = msg[6:]

        en_bytes = b''
        cn_bytes = []

        for i, d in enumerate(data):
            nv = chr(d ^ masks[i % 4])
            nv_bytes = nv.encode()
            nv_len = len(nv_bytes)
            if nv_len == 1:
                en_bytes += nv_bytes
            else:
                en_bytes += b'%s'
                cn_bytes.append(ord(nv_bytes.decode()))

        if len(cn_bytes) > 2:
            cn_str = ''
            clen = len(cn_bytes)
            count = int(clen / 3)
            for x in range(count):
                i = x * 3
                b = bytes([cn_bytes[i], cn_bytes[i + 1], cn_bytes[i + 2]])
                cn_str += b.decode()
            new = en_bytes.replace(b'%s%s%s', b'%s')
            new = new.decode()
            res = (new % tuple(list(cn_str)))
        else:
            res = en_bytes.decode()
        return res


class WebSocketServer:
    """ Python实现WebSocket """

    # 地址
    __address = None
    # 端口
    __port = None

    # 主线程
    __master = None

    # 客户socket
    __clients = {}

    # 消息回调列表
    __callbacks = []

    def __init__(self, address, port):
        """ 初始化 """
        self.__address = address
        self.__port = port

        self.__master = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__master.bind((self.__address, self.__port))
        self.__master.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__master.listen(50)

        self.__log('初始化完成')

    def get_client(self, name):
        """
        获取客户端
        :param name 客户端的名称
        """
        return self.__clients[name] if name in self.__clients else None

    def get_clients(self):
        """ 获取所有客户端 """
        return self.__clients

    def disconnect_client(self, name):
        """ 根据名称断开与客户端的连接 """
        if name in self.__clients:
            try:
                self.__clients[name].get_conn().close()
            finally:
                self.__log('[' + name + ']断开连接')
                del self.__clients[name]

    def add_callback(self, callback):
        """
        添加消息回调
        :param callback: 消息回调, 回调方法(client, message)
        """
        self.__callbacks.append(callback)

    def remove_callback(self, callback):
        """
        移除回调
        :param callback: 被移除的回调
        """
        self.__callbacks.remove(callback)

    def get_callbacks(self):
        """ 获取回调列表 """
        return self.__callbacks

    def run_forever(self):
        """ 开启服务 """
        self.__log('启动')

        i = 0

        while True:
            self.__log('等待连接')
            client_socket, address_info = self.__master.accept()
            self.__log(address_info[0] + '申请连接')

            client = WebSocketClient(client_socket, address_info, str(i), self)
            client.start()

            self.__clients[str(i)] = client

            i += 1

    def close(self):
        """ 关闭服务 """
        for _, c in self.__clients.items():
            c.close()
        self.__master.close()

    def __log(self, msg):
        print(self.__address + ':' + str(self.__port) + ': ' + msg)


if __name__ == '__main__':
    ws = WebSocketServer('localhost', 8080)
    try:
        ws.run_forever()
    finally:
        ws.close()
