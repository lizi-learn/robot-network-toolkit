"""Read the same diagnostic and Ethernet information used by the chassis UI."""
import base64
import hashlib
import json
import os
import struct


def read_status(robot, host, port):
    sock = robot.get_transport().open_channel(
        'direct-tcpip', (host, port), ('127.0.0.1', 0))
    sock.settimeout(15)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f'GET / HTTP/1.1\r\nHost: {host}:{port}\r\n'
                  'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                  'Sec-WebSocket-Key: ' + key + '\r\n'
                  'Sec-WebSocket-Version: 13\r\n\r\n').encode())

    def exact(count):
        output = b''
        while len(output) < count:
            part = sock.recv(count - len(output))
            if not part:
                raise EOFError('Chassis closed the connection')
            output += part
        return output

    def send(payload, opcode=1):
        if isinstance(payload, str):
            payload = payload.encode()
        mask = os.urandom(4)
        count = len(payload)
        header = (bytes([128 | opcode, 128 | count]) if count < 126 else
                  bytes([128 | opcode, 254]) + struct.pack('!H', count))
        sock.sendall(header + mask + bytes(
            value ^ mask[i % 4] for i, value in enumerate(payload)))

    def receive():
        while True:
            first, second = exact(2)
            count = second & 127
            if count == 126:
                count = struct.unpack('!H', exact(2))[0]
            elif count == 127:
                count = struct.unpack('!Q', exact(8))[0]
            if count > 1000000:
                raise ValueError('Unexpectedly large chassis response')
            mask = exact(4) if second & 128 else None
            payload = exact(count)
            if mask:
                payload = bytes(value ^ mask[i % 4]
                                for i, value in enumerate(payload))
            opcode = first & 15
            if opcode == 9:
                send(payload, 10)
            elif opcode == 1:
                return json.loads(payload)
            elif opcode == 8:
                raise EOFError('Chassis closed the WebSocket')

    try:
        headers = b''
        while b'\r\n\r\n' not in headers:
            headers += exact(1)
            if len(headers) > 16384:
                raise ValueError('Invalid WebSocket handshake')
        expected = base64.b64encode(hashlib.sha1(
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        if b'101 Switching Protocols' not in headers or expected not in headers:
            raise ValueError('WebSocket handshake rejected')
        results = {}
        for index, (name, service, command) in enumerate([
            ('diagnosis', '/bash_services/diagnosis', 'get_result'),
            ('ethernet', '/bash_services/ethernet', 'info'),
        ]):
            request_id = 'codex-readonly-' + str(index)
            send(json.dumps({'op': 'call_service', 'id': request_id,
                             'service': service, 'type': 'water_msgs/CmdService',
                             'args': {'cmd': command, 'message': ''}}))
            while True:
                result = receive()
                if result.get('id') == request_id:
                    break
            if not result.get('values', {}).get('success'):
                raise RuntimeError(str(result))
            results[name] = json.loads(result['values']['message'])
        send(b'', 8)
        return results
    finally:
        sock.close()
