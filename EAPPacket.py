import random
import struct


class EAPPacket:
    """
    EAP (Extensible Authentication Protocol) Packet
    """

    """
    Request packet
    """
    CODE_REQUEST = 1

    """
    Response packet
    """
    CODE_RESPONSE = 2

    """
    Success packet
    """
    CODE_SUCCESS = 3

    """
    Failure packet
    """
    CODE_FAILURE = 4

    TYPE_IDENTITY = 1
    TYPE_NOTIFICATION = 2
    TYPE_NAK = 3
    TYPE_MD5_CHALLENGE = 4
    TYPE_OTP = 5
    TYPE_GENERIC_TOKEN = 6
    TYPE_EAP_MS_AUTH = 26

    def __init__(self):
        self.id = None
        self.code = None
        self.type = None
        self.data = None

    def set_id(self, identifier):
        """
        Set the EAP identifier.

        If the provided id the None, a random value is used.

        :param identifier: the identifier
        :type identifier: int
        """
        if not identifier:
            self.id = random.randint(0, 255)
        else:
            self.id = identifier

    def __bytes__(self):
        """
        Returns the bytes representation of the packet

        :return: the bytes
        :rtype: bytes
        """

        # The packet is structured like this :
        #   - the code of the packet on 1 byte
        #   - the identifier on 1 byte
        #   - the length on 2 bytes, big-endian
        #   - the type of the packet on 1 byte
        #   - the encapsuled data

        struct.pack('B', self.id)
        struct.pack('B', self.type)

        return struct.pack('B', self.code) + \
               struct.pack('B', self.id) + \
               struct.pack('>H', 5 + len(self.data)) + \
               struct.pack('B', self.type) + \
               self.data

    @staticmethod
    def identity(identity, identifiier=None):
        """
        Get the bytes of a EAP packet with the code RESPONSE, the type IDENTITY, the provided identity data and
        identifier.

        :param identity: the identity data bytes
        :type identity: bytes
        :param identifiier: the identifier
        :type identifiier: int|None
        :return: the packet bytes data
        :rtype: bytes
        """
        packet = EAPPacket()
        packet.set_id(identifiier)
        packet.code = EAPPacket.CODE_RESPONSE
        packet.type = EAPPacket.TYPE_IDENTITY
        packet.data = identity

        return packet.__bytes__()

    @staticmethod
    def legacyNak(identifiier=None):
        """
        Get the bytes of a EAP packet with the code RESPONSE, the type EAP_MS_AUTH, the provided MSCHAP packet data and
        identifier.

        :param identifiier: the identifier
        :type identifiier: int|None
        :return: the packet bytes data
        :rtype: bytes
        """

        packet = EAPPacket()
        packet.set_id(identifiier)
        packet.code = EAPPacket.CODE_RESPONSE
        packet.type = EAPPacket.TYPE_NAK
        packet.data = bytearray([EAPPacket.TYPE_EAP_MS_AUTH])

        return packet.__bytes__()

    @staticmethod
    def mschapv2(mschapv2_packet, identifiier=None):
        """
        Get the bytes of a EAP packet with the code RESPONSE, the type EAP_MS_AUTH, the provided MSCHAP packet data and
        identifier.

        :param mschapv2_packet: the MSCHAPv2 packet
        :type mschapv2_packet: MSCHAPv2Packet
        :param identifiier: the identifier
        :type identifiier: int|None
        :return: the packet bytes data
        :rtype: bytes
        """

        packet = EAPPacket()
        packet.set_id(identifiier)
        packet.code = EAPPacket.CODE_RESPONSE
        packet.type = EAPPacket.TYPE_EAP_MS_AUTH
        packet.data = mschapv2_packet.__bytes__()

        return packet.__bytes__()

    @staticmethod
    def from_bytes(b):
        """
        Create a EAPPacket from the bytes provided.

        The packet always begins with :
            - the code on 1 byte
            - the identifier on 1 byte
            - the length on 2 bytes, big-endian

        The packet can also contain a type and data.

        :param b: packet data
        :type b: bytes
        :return: the EAPPacket
        :rtype: EAPPacket
        :raise ValueError: if the bytes is malformed
        """
        if len(b) < 4:
            raise ValueError('Packet is too small')

        packet = EAPPacket()
        packet.code = b[0]
        packet.id = b[1]
        size = struct.unpack('>H', b[2:4])[0] - 5

        if len(b) != size + 5:
            raise ValueError('Packet length is incorrect')

        if len(b) > 4:
            packet.type = b[4]
            packet.data = b[5:]

        return packet
