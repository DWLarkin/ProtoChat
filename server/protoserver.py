#!/usr/bin/env python3
"""Defines and potentially runs a ProtoChat server."""
import argparse
import logging
import select
import socket
import struct
import sys
import uuid

from enum import IntEnum, auto
from typing import Optional


class NetworkConstants(IntEnum):
    MAX_LEN = 4096
    MAX_NAME = 255  # Including \0, when it comes to outbound
    HELLO_HDR_LEN = 2
    MAX_HELLO = MAX_NAME + HELLO_HDR_LEN
    BASE_HDR_LEN = 3
    CHAT_HDR_LEN = BASE_HDR_LEN + 1


class ProtocolCodes(IntEnum):
    INVALID_CODE = 0
    CLIENT_HELLO = auto()
    SERVER_ACK = auto()
    CHAT_MESSAGE = auto()
    CLIENT_DISCONNECT = auto()
    FILE_UPLOAD = auto()
    FILE_DOWNLOAD = auto()
    OUT_OF_BOUNDS = auto()


def validate_groupname(user_input):
    """Validates a groupname

    Args:
        user_input (any): The input to check.

    Raises:
        ValueError: If the input doesn't contain a valid groupname.

    """
    groupname = str(user_input)
    encoded_groupname = groupname.encode("utf-8")
    if len(encoded_groupname) > NetworkConstants.MAX_NAME - 1:
        raise ValueError("Group names cannot exceed 254 bytes when encoded.")

    return groupname


def validate_ip(user_input):
    """Validates a string representation of an IP.

    Args:
        user_input (any): The input to check.

    Raises:
        ValueError: If the input doesn't contain a stringified address.

    """
    str_input = str(user_input)

    try:
        socket.inet_pton(socket.AF_INET, str_input)
        return str_input
    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, str_input)
        return str_input
    except OSError:
        pass

    raise ValueError("Invalid address")


def parse_proto_args() -> argparse.Namespace:
    """Parses the arguments for a ProtoChat server.

    Returns:
        An argparse namespace containing the arguments.

    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "groupname",
        type=validate_groupname,
        help="The name given to the chat group.",
    )
    parser.add_argument(
        "-a",
        "--address",
        type=validate_ip,
        required=False,
        default="0.0.0.0",
        help="The IPv4 or IPv6 address the server should on.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        required=False,
        default=1337,
        help="The port that the server should listen on.",
    )

    return parser.parse_args()


def check_address_family(str_addr: str) -> socket.AddressFamily:
    """Checks for the family of a stringified address.

    Args:
        str_addr (str): A string containing a valid IP address.

    Returns:
        Either socket.AF_INET or socket.AF_INET6.

    Raises:
        ValueError: If the string doesn't contain a valid address.

    """
    if "." in str_addr:
        return socket.AF_INET
    if ":" in str_addr:
        return socket.AF_INET6
    raise ValueError("String does not contain an address")


def send_all(conn: socket.socket, data: bytes, logger: logging.Logger) -> int:
    """Attempts to send all provided data.

    Args:
        conn (socket.socket): The socket to send on.
        data (bytes): The data to send.
        logger (logging.Logger): The logger to output to.

    Returns:
        The number of bytes sent, or -1 on disconnection or send error.

    """
    total_sent = 0

    logger.debug(f"Calling send with bytes {data.hex(sep=" ")}")

    try:
        while data:
            to_send = data[:NetworkConstants.MAX_LEN]

            bytes_sent = conn.send(to_send, 0)
            if bytes_sent == 0:
                logger.info("Client disconnected")
                return -1

            data = data[bytes_sent:]
            total_sent += bytes_sent

        return total_sent
    except BlockingIOError:
        return total_sent
    except OSError as err:
        logger.error(f"Send failure: {err}")
        return -1


def recv_all(conn: socket.socket, length: int, logger: logging.Logger) -> bytes:
    """Attempts to recv all requested bytes.

    Args:
        conn (socket.socket): The socket to recv on.
        length (int): The number of bytes to recv.
        logger (logging.Logger): The logger to output to.

    Returns:
        Whatever bytes are received, or no bytes on socket disconnect/error.

    """
    all_received = bytearray()
    amt_remaining = length

    while amt_remaining > 0:
        recv_amt = NetworkConstants.MAX_LEN if amt_remaining > NetworkConstants.MAX_LEN else amt_remaining

        try:
            recv_ret = conn.recv(recv_amt, 0)
            logger.info(f"Got bytes: {recv_ret.hex(sep=" ")}")
        except BlockingIOError:
            return all_received
        except OSError as err:
            logger.error(f"Recv failure: {err}")
            return bytes()

        if not recv_ret:
            logger.info("Client disconnected")
            return bytes()

        all_received += recv_ret
        amt_remaining -= len(recv_ret)

    return all_received


# TODO: see if I can convert these to dataclasses
class Task:

    """Base class for packet types for inheritance + typehinting."""

    def __init__(self, task_type: ProtocolCodes):
        self.task_type = task_type

    def pack(self) -> bytes:
        """Packs tasks into serialized data based off provided values.

        Returns:
            A packet representing the task object.

        """
        return struct.pack("!B", self.task_type)


class TaskChatMsg(Task):
    """Header + payload handler for chat messages."""
    
    def __init__(self, name: str, data: bytes):
        """Initialize chat message class."""
        super().__init__(ProtocolCodes.CHAT_MESSAGE)
        self.name = name
        self.data = data

    def pack(self) -> bytes:
        """Creates a chat message packet based off provided values.

        Returns:
            The serialized chat message packet.

        """
        encoded_name = (self.name + '\x00').encode("utf-8")
        assert len(encoded_name) <= 255
        assert len(self.data) <= 65535

        return struct.pack(
            f"!BHB{len(encoded_name)}s{len(self.data)}s",
            self.task_type,
            len(self.data) + len(encoded_name) + 1,
            len(encoded_name),
            encoded_name,
            self.data,
        )


class TaskDisconnect(Task):
    """Header + payload handler for client disconnections."""

    def __init__(self, name: str):
        super().__init__(ProtocolCodes.CLIENT_DISCONNECT)
        self.name = name

    def pack(self) -> bytes:
        """Creates a disconnect notification packet based off provided name.

        Returns:
            The serialized disconnect packet.

        """
        encoded_name = (self.name + '\x00').encode("utf-8")
        assert len(encoded_name) <= 255

        return struct.pack(
            f"!BHB{len(encoded_name)}s",
            self.task_type,
            len(encoded_name) + 1,
            len(encoded_name),
            encoded_name
        )

class ProtoClient:
    """Class-based handler for ProtoChat clients."""

    def __init__(self, conn: socket.socket, groupname: str, logger: logging.Logger):
        """Initializes the client object."""
        self.name = None
        self.groupname = groupname
        self.conn = conn
        self.inbound_data = bytearray()
        self.outbound_data = bytearray()
        self.pending_tasks: list[Task] = []
        self.broadcast_tasks: list[Task] = []
        self.logger = logger

    def handle_client_hello(self):
        """Receives a hello request from a new client and sends an ack."""
        # Nothing should ever get sent here besides the client hello.
        recv_bytes = recv_all(self.conn, NetworkConstants.MAX_HELLO, self.logger)
        if not recv_bytes:
            self.close()
            raise ConnectionResetError("Client disconnected unexpectedly")

        self.inbound_data += recv_bytes

        if len(self.inbound_data) >= NetworkConstants.HELLO_HDR_LEN:  # Task code and name length
            if self.inbound_data[0] != ProtocolCodes.CLIENT_HELLO:
                self.close()
                raise ConnectionResetError("Received bad code from invalid endpoint, closed socket")

            if self.inbound_data[1] > len(self.inbound_data[NetworkConstants.HELLO_HDR_LEN:]):
                return
            if self.inbound_data[1] < len(self.inbound_data[NetworkConstants.HELLO_HDR_LEN:]):
                self.close()
                raise ConnectionResetError("Received bad data from invalid endpoint, closed socket")

            try:
                self.name = (self.inbound_data[NetworkConstants.HELLO_HDR_LEN:]).decode("utf-8")
            except UnicodeDecodeError:
                self.close()
                raise ConnectionResetError("Received bad name from invalid endpoint, closed socket")

            self.logger.info(f"Client {self.name} has connected!")

            self.inbound_data = bytearray()

            # TODO: The ack won't really be necessary when TLS is implemented.
            encoded_name = (self.groupname + '\x00').encode("utf-8")
            server_ack = struct.pack(
                f"!BB{len(encoded_name)}s",
                ProtocolCodes.SERVER_ACK,
                len(encoded_name),
                encoded_name,
            )

            self.outbound_data += server_ack

    def handle_chat_message(self):
        _, _, name_len = struct.unpack(
            f"!BHB",
            self.inbound_data[:NetworkConstants.CHAT_HDR_LEN]
        )

        encoded_name = self.inbound_data[NetworkConstants.CHAT_HDR_LEN:name_len]
        msg = self.inbound_data[(NetworkConstants.CHAT_HDR_LEN + name_len):]

        try:
            decoded_name = encoded_name.decode("utf-8")
        except UnicodeDecodeError:
            self.conn.close()
            raise ConnectionResetError("Bad data in client packet")

        self.broadcast_tasks.append(TaskChatMsg(decoded_name, msg))

    def handle_client_disc(self) -> TaskDisconnect:
        # TODO
        self.logger.info("Doing disconnect things")

    def handle_inbound_task(self):
        hdr_remaining = NetworkConstants.BASE_HDR_LEN - len(self.inbound_data)
        recv_bytes = recv_all(self.conn, hdr_remaining, self.logger)
        if not recv_bytes:
            self.close()
            raise ConnectionResetError("Client disconnected")

        self.inbound_data += recv_bytes

        if len(self.inbound_data) >= NetworkConstants.BASE_HDR_LEN:
            task_code, data_len = struct.unpack("!BH", self.inbound_data[:3])
            data_remaining = data_len - (len(self.inbound_data) + NetworkConstants.BASE_HDR_LEN)

            recv_bytes = recv_all(self.conn, data_remaining, self.logger)
            if not recv_bytes:
                self.close()
                raise ConnectionResetError("Client disconnected")

            if len(self.inbound_data) >= NetworkConstants.BASE_HDR_LEN + data_len:
                match task_code:
                    case ProtocolCodes.CHAT_MESSAGE:
                        self.handle_chat_message()
                    case ProtocolCodes.CLIENT_DISCONNECT:
                        self.handle_client_disc()
                    case ProtocolCodes.FILE_UPLOAD:
                        pass  # TODO
                    case ProtocolCodes.FILE_DOWNLOAD:
                        pass  # TODO
                    case _:
                        self.close()
                        raise ConnectionResetError("Invalid task code received from client")

    def handle_read(self):
        if self.name is None:
            self.handle_client_hello()
        else:
            self.handle_inbound_task()

    def handle_write(self):
        if self.outbound_data:
            sent = send_all(self.conn, self.outbound_data, self.logger)
            if sent == -1:
                self.close()
                raise ConnectionResetError("Failed to send data to client")
            self.outbound_data = self.outbound_data[sent:]
            return

        if self.pending_tasks:
            self.outbound_data += self.pending_tasks[0].pack()
            self.pending_tasks.pop(0)

    def close(self):
        """Closes the client connection."""
        self.conn.close()


class ProtoServer:
    """Class-based handler for server functionality."""

    def __init__(self, groupname: str, address: str, port: int, logger: logging.Logger):
        """Initializes the ProtoChat server and starts the listening socket."""
        self.groupname = groupname
        self.bind_address = address
        self.bind_port = port
        self.servsock: socket.socket | None = None
        self.clients: list[ProtoClient] = []
        self.logger = logger

        self.start_listening()

    def start_listening(self):
        """Starts a server socket and begins listening on it.

        Raises:
            RuntimeError: If one of the socket calls fails.

        """
        try:
            self.servsock = socket.create_server(
                (self.bind_address, self.bind_port),
                family=check_address_family(self.bind_address),
                reuse_port=True,
            )

            self.servsock.setblocking(False)

            self.servsock.listen(5)
        except OSError as err:
            raise RuntimeError("failed to create ProtoChat server") from err

    def create_select_lists(self) -> tuple[list, list, list]:
        rlist = [client.conn for client in self.clients]
        wlist = [client.conn for client in self.clients if client.pending_tasks or client.outbound_data]
        xlist = [client.conn for client in self.clients]

        rlist.append(self.servsock)
        xlist.append(self.servsock)

        return (rlist, wlist, xlist)

    def broadcast_tasks(self):
        # TODO: This could def be more efficient when I get time.
        for client in self.clients:
            broadcast_recipients = [recipient for recipient in self.clients if recipient.name != client.name]
            for broadcast in client.broadcast_tasks:
                for recipient in broadcast_recipients:
                    recipient.pending_tasks.append(broadcast)
            client.broadcast_tasks = []

    def run_server(self):
        """Runs the ProtoChat server, accepting and handling clients."""
        try:
            while True:
                rlist, wlist, xlist = self.create_select_lists()

                self.logger.debug("Selecting")
                r_ready, w_ready, x_ready = select.select(rlist, wlist, xlist)
                self.logger.debug("Things have been selected")
                for i, client in enumerate(self.clients):
                    try:
                        if client.conn in w_ready:
                            client.handle_write()

                        if client.conn in r_ready:
                            client.handle_read()
                    except ConnectionResetError:
                        # TODO: let other clients know about sudden disconnects
                        self.logger.info(f"Removing configuration for client {client.name}")
                        self.clients.pop(i)

                    if client.conn in x_ready:
                        self.logger.error(f"Client {client.name} had an unexpected socket error")
                        client.close()
                        self.clients.pop(i)

                if self.servsock in r_ready:
                    conn, cliaddr = self.servsock.accept()
                    conn.setblocking(False)

                    new_client = ProtoClient(conn, self.groupname, self.logger)
                    self.clients.append(new_client)

                    self.logger.info(f"New connection from {cliaddr[0]}:{cliaddr[1]}")

                if self.servsock in x_ready:
                    self.logger.error("Something went wrong with the server socket")
                    self.close()
                    break

                self.broadcast_tasks()

        except KeyboardInterrupt:
            self.close()

    def close(self):
        """Closes the server's resources."""
        for client in self.clients:
            client.close()
        self.servsock.close()


def main(args: argparse.Namespace):
    slogger = logging.getLogger("ProtoServer")
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    server_obj = ProtoServer(args.groupname, args.address, args.port, slogger)
    server_obj.run_server()

    logging.shutdown()


if __name__ == "__main__":
    args = parse_proto_args()
    main(args)
