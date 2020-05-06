import socket

ADDRESS = [
    b"\x00",
    b"\x01",
    b"\x02",
    b"\x03",
    b"\x04",
    b"\x05",
    b"\x06",
    b"\x07",
    b"\x08",
    b"\x09",
    b"\x0A",
    b"\x0B",
    b"\x0C",
    b"\x0D",
    b"\x0E",
    b"\x0F",
]


class ConnectLocker:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.stx = b'\x02'
        self.etx = b'\x03'
        self.cmd_open = b'\x31'
        self.cmd_status = b'\x30'
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def checksum_calc(self, data):
        checksum = 0
        for ch in data:
            checksum += ord(ch)
        hex_check = hex(checksum % 256)
        return hex_check

    def connect_locker(self):
        try:
            self.socket.connect((self.ip, self.port))
        except Exception as e:
            print(e)

    def recv_locker(self, port):
        try:
            result_status = self.checksum_calc(
                [self.stx, ADDRESS[port], self.cmd_status, self.etx])

            checksum_status = chr(int(result_status, 16)).encode('utf-8')
            self.socket.send(
                self.stx+ADDRESS[port]+self.cmd_status+self.etx+checksum_status)

            data = self.socket.recv(1024)
            if data == b'\x02\x005\x00\x00\x00\x00\x03:':
                print(f'Porta {port + 1} Aberta')
            else:
                print(f'Porta {port + 1} Fechada')
        except Exception as e:
            print(e)

    def open_locker(self, port):
        try:
            result_open = self.checksum_calc(
                [self.stx, ADDRESS[port], self.cmd_open, self.etx])

            checksum_open = chr(int(result_open, 16)).encode('utf-8')
            self.socket.send(
                self.stx+ADDRESS[port]+self.cmd_open+self.etx+checksum_open)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    connect_locker = ConnectLocker(ip='192.168.0.178', port=5000)
    connect_locker.connect_locker()
    connect_locker.open_locker(0)
