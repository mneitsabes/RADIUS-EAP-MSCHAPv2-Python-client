import struct
import hashlib
import binascii

from Crypto.Hash import MD4
from Crypto.Cipher import DES

class VendorSpecificPacket:
    """
    Vendor Specific Packet
    """

    """
    Microsoft Vendor Code
    """
    VENDOR_MICROSOFT = 311

    """
    MSCHAPv2 Challenge type
    """
    TYPE_MSCHAP_CHALLENGE = 11

    """
    MSCHAPv2 Challenge Response type
    """
    TYPE_MSCHAP_RESPONSE = 25

    def __init__(self, vendor, type, value):
        """

        :param vendor: the vendor code
        :type vendor: int
        :param type: the type code
        :type type: int
        :param value: the value
        :type value: bytes
        """
        self.vendor = vendor
        self.type = type
        self.value = value

    def __bytes__(self):
        """
        Returns the bytes representation of the packet

        :return: the bytes
        :rtype: bytes
        """
        packet = bytearray()
        packet += b'\x00\x00'  # for the vendor
        packet += struct.pack('>H', self.vendor)
        packet += struct.pack('B', self.type)
        packet += struct.pack('B', len(self.value) + 2)
        packet += self.value
        return packet

class MSCHAPv2Response:
    """
    MSCHAPv2 (legacy) response
    """

    def __init__(self, challenge, response):
        """

        :param challenge: the peer challenge
        :type challenge: bytes
        :param response: the challenge response
        :type response: bytes
        """        
        self.challenge = challenge
        self.response = response

    def __bytes__(self):
        """
        Returns the bytes representation of the response

        :return: the bytes
        :rtype: bytes
        """
        packet = bytearray()
        packet += b'\x00' * 2
        packet += self.challenge
        packet += b'\x00' * 8
        packet += self.response
        return packet

class MSCHAPv2Packet:
    """
    MSChapv2 packet
    """

    """
    Challenge packet
    """
    OPCODE_CHALLENGE = 1

    """
    Response packet
    """
    OPCODE_RESPONSE = 2

    """
    Success packet
    """
    OPCODE_SUCCESS = 3

    """
    Failure packet
    """
    OPCODE_FAILURE = 4

    def __init__(self, opcode):
        """

        :param opcode: the opcode
        :type opcode: int
        :param ms_chap_id: the MSCHAP identifier
        :type ms_chap_id: int
        """
        if opcode < 1 or opcode > 4:
            raise ValueError('Unknown opcode')

        self.opcode = opcode

        self.ms_chap_id = None
        self.ms_length = None
        self.value_size = None
        self.challenge = None
        self.response = None
        self.name = None

    def __bytes__(self):
        """
        Returns the bytes representation of the packet

        :return: the bytes
        :rtype: bytes
        """
        # If the Op code is success or failure, it's juste the value of the opcode
        if self.opcode == MSCHAPv2Packet.OPCODE_SUCCESS or self.opcode == MSCHAPv2Packet.OPCODE_FAILURE:
            return struct.pack('B', self.opcode)

        # A challenge or response packet is structured like this :
        #   - the opcode on 1 byte
        #   - the MSCHAP identifier on 1 byte
        #   - the length on 2 bytes, big-endian
        #
        # If this is a challenge, the packet must also contains :
        #   - the length of the challenge (16) on 1 byte
        #   - the challenge (bytes)
        #   - the name (bytes)
        #
        # If this is a response, the packet must also contains
        #   - the length, 49, on 1 byte
        #   - the challenge (bytes)
        #   - 8 nul bytes reserved
        #   - the response
        #   - 1 nul byte
        #   - the name

        packet = bytearray()
        packet += struct.pack('B', self.opcode)
        packet += struct.pack('B', self.ms_chap_id)
        packet += b'\x00\x00'  # for the length

        if self.opcode == MSCHAPv2Packet.OPCODE_CHALLENGE:
            packet += struct.pack('B', len(self.challenge))
            packet += self.challenge
            packet += self.name
        elif self.opcode == MSCHAPv2Packet.OPCODE_RESPONSE:
            packet += struct.pack('B', 49)
            packet += self.challenge
            packet += b'\x00' * 8
            packet += self.response
            packet += b'\x00'
            packet += self.name

        # Compute the final length and put this value on the reserved slot on the begin of the packet
        length = struct.pack('>H', len(packet))
        packet[2] = length[0]
        packet[3] = length[1]

        return packet

    def __str__(self):
        """
        String respresentation of this packet.

        :return: the representation
        :rtype: str
        """
        resp = binascii.hexlify(self.response) if self.response else None
        s = f'Opcode: {self.opcode}\n'
        s += f'MsChapId: {self.ms_chap_id}\n'
        s += f'MsLength: {self.ms_length}\n'
        s += f'ValueSize: {self.value_size}\n'
        s += f'Challenge: {binascii.hexlify(self.challenge)}\n'
        s += f'Response: {resp}\n'
        s += f'Name: {self.name} ({binascii.hexlify(self.name)})\n'

        return s

    @staticmethod
    def from_bytes(b):
        """
        Create a MSCHAPv2Packet from the bytes provided.

        See __bytes__() for the packet structure.

        :param b: packet data
        :type b: bytes
        :return: the MSCHAPv2Packet
        :rtype: MSCHAPv2Packet
        :raise ValueError: if the bytes is malformed
        """
        if len(b) < 5:
            raise ValueError('Packet is too small')

        packet = MSCHAPv2Packet(b[0])
        packet.ms_chap_id = b[1]
        packet.ms_length = struct.unpack('>H', b[2:4])[0]
        packet.value_size = b[4]

        if packet.ms_length != len(b):
            raise ValueError('Packet length is incorrect')

        if packet.opcode == MSCHAPv2Packet.OPCODE_CHALLENGE:
            packet.challenge = b[5:5 + packet.value_size]
            packet.name = b[5 + packet.value_size:]
        elif packet.opcode == MSCHAPv2Packet.OPCODE_FAILURE:
            packet.response = b[5:]

        return packet


class MSCHAPv2Crypto:
    """
    Handles all crypto for the MSCHAPv2 protocol
    """
    def __init__(self, chap_id, auth_challenge, peer_challenge, username, password):
        """

        :param chap_id: the MSCHAP identifier
        :type chap_id: int
        :param auth_challenge: the challenge/response of the challenge
        :type auth_challenge: bytes
        :param peer_challenge: the peer challenge
        :type peer_challenge: bytes
        :param username: the username, bytes encoded
        :type username: bytes
        :param password: the password, as a string
        :type password: str
        """
        self.chap_id = chap_id

        self.auth_challenge = auth_challenge
        self.peer_challenge = peer_challenge

        self.username = username
        self.password = password

    def challenge_response(self):
        """
        Compute the response challenge based on the :
            - the auth challenge
            - the peer challenge
            - the MSCHAP identifier
            - the username
            - the password

        A challenge hash is computed, see _get_challenge_hash().

        A NT hash password is computed from the provided password, see nt_password_hash().

        This challenge hash is then encrypted 3 times with DES. Each cipher used a part the nt hash password for the
        key. The three encrypted data are merged to create the challenge response.

        :return: the challenge response
        :rtype: bytes
        """
        challenge_hash = self._get_challenge_hash()

        nt_password_hash = self.nt_password_hash(self.password)
        nt_password_hash += b'\x00' * (21 - len(nt_password_hash))  # We must pad to 21 chars

        cipher1 = DES.new(self._des_add_parity(nt_password_hash[0:7]), DES.MODE_ECB)
        cipher2 = DES.new(self._des_add_parity(nt_password_hash[7:14]), DES.MODE_ECB)
        cipher3 = DES.new(self._des_add_parity(nt_password_hash[14:21]), DES.MODE_ECB)

        return cipher1.encrypt(challenge_hash) + cipher2.encrypt(challenge_hash) + cipher3.encrypt(challenge_hash)

    def _get_challenge_hash(self):
        """
        Compute the challenge hash.

        The challenge hash is the first 8 bytes of the SHA1 of :
            - the peer challenge
            - the auth challenge
            - the username

        :return: 8 bytes
        :rtype: bytes
        """
        sha1_ctx = hashlib.sha1()
        sha1_ctx.update(self.peer_challenge)
        sha1_ctx.update(self.auth_challenge)
        sha1_ctx.update(self.username)

        return sha1_ctx.digest()[:8]

    @staticmethod
    def nt_password_hash(password):
        """
        Compute the NT password hash.

        It's the MD4 hash of the password encoded in UTF-16 bits little-endian.

        :param password: the password
        :type password: str
        :return: the bytes
        :type bytes
        """
        ctx = MD4.new()
        ctx.update(password.encode("utf-16le"))
        return ctx.digest()

    @staticmethod
    def divide_chunks(l, n):
        """
        Divide the provided l list with sublist of n items, as a generator.

        :param l: the list
        :type l: list
        :param n: the number of items per chunk
        :type n: int
        :return: subset of list
        :rtype: list
        """
        # looping till length l
        for i in range(0, len(l), n):
            yield l[i:i + n]

    @staticmethod
    def _des_add_parity(key):
        """
        Add the parity bit for the given DES key.

        All bits of the key are merged. Each 7 bits are merged with the least-significant bit to 0 to create a index.
        The value in odd_parity is fetched with this index to get the new character of the key.

        Exemple with the key 'ab':

            a = 0110 0001
            b : 0110 0010

        Full bits = 0110 0001 0110 0010. Split with 7 bytes :
            * 0110 000
            * 1011 000
            * 10

        Adding 0 for the least significant bit :
            * 0110 0000
            * 1011 0000
            * 100

        In dec :
            * 96
            * 176
            * 4

        In the odd parity :
            * odd_parity[96] = 97
            * odd_parity[176] = 176
            * odd_parity[4] = 4

        Back the bytes, the final key is 0x61 0xB0 0x04.

        :param key: the DES key
        :type key bytes:
        :return: the altered key
        :rtype: bytes
        """
        odd_parity = [
            1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
            16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
            32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
            49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
            64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
            81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
            97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
            112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
            128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
            145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
            161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
            176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
            193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
            208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
            224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
            241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
        ]

        # Git all bits in the array as bool value
        bits = []
        for i in range(0, len(key)):
            bits.extend(reversed([bool(key[i] & (1 << n)) for n in range(8)]))

        key = b''
        for chunk in MSCHAPv2Crypto.divide_chunks(bits, 7):
            # Get a chunk of 7 bits and add the least significant bit to 0 (False)
            chunk.append(False)

            # Recreate the value based on the array
            i = sum(v << i for i, v in enumerate(chunk[::-1]))

            # Get the char key value
            key += struct.pack('B', odd_parity[i])

        return key
    
