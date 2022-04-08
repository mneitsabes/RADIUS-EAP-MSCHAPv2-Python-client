import struct
import socket
import hashlib
import random

from Crypto.Hash import HMAC, MD5

from .EAPPacket import EAPPacket
from .MSCHAPv2 import MSCHAPv2Packet, MSCHAPv2Crypto, VendorSpecificPacket, MSCHAPv2Response


class RADIUSPacket:
    """
    RADIUS Packet
    """

    """
    Access request
    """
    TYPE_ACCESS_REQUEST = 1

    """
    Access accept
    """
    TYPE_ACCESS_ACCEPT = 2

    """
    Access reject
    """
    TYPE_ACCESS_REJECT = 3

    """
    Access challenge
    """
    TYPE_ACCESS_CHALLENGE = 11

    """
    Attributes information structured like this :
        <type> : [<name>, <attr_type>]
        
    where attr_type can be :
        S (string) / T (text)
        A (IPv4 address)
        I (Integer)
        D (Date)
    """
    ATTRIBUTES_INFO = {
        1: ['User-Name', 'S'],
        2: ['User-Password', 'S'],
        3: ['CHAP-Password', 'S'],
        4: ['NAS-IP-Address', 'A'],
        5: ['NAS-Port', 'I'],
        6: ['Service-Type', 'I'],
        7: ['Framed-Protocol', 'I'],
        8: ['Framed-IP-Address', 'A'],
        9: ['Framed-IP-Netmask', 'A'],
        10: ['Framed-Routing', 'I'],
        11: ['Filter-Id', 'T'],
        12: ['Framed-MTU', 'I'],
        13: ['Framed-Compression', 'I'],
        14: ['Login-IP-Host', 'A'],
        15: ['Login-service', 'I'],
        16: ['Login-TCP-Port', 'I'],
        17: ['(unassigned)', ''],
        18: ['Reply-Message', 'T'],
        19: ['Callback-Number', 'S'],
        20: ['Callback-Id', 'S'],
        21: ['(unassigned)', ''],
        22: ['Framed-Route', 'T'],
        23: ['Framed-IPX-Network', 'I'],
        24: ['State', 'S'],
        25: ['Class', 'S'],
        26: ['Vendor-Specific', 'S'],
        27: ['Session-Timeout', 'I'],
        28: ['Idle-Timeout', 'I'],
        29: ['Termination-Action', 'I'],
        30: ['Called-Station-Id', 'S'],
        31: ['Calling-Station-Id', 'S'],
        32: ['NAS-Identifier', 'S'],
        33: ['Proxy-State', 'S'],
        34: ['Login-LAT-Service', 'S'],
        35: ['Login-LAT-Node', 'S'],
        36: ['Login-LAT-Group', 'S'],
        37: ['Framed-AppleTalk-Link', 'I'],
        38: ['Framed-AppleTalk-Network', 'I'],
        39: ['Framed-AppleTalk-Zone', 'S'],
        60: ['CHAP-Challenge', 'S'],
        61: ['NAS-Port-Type', 'I'],
        62: ['Port-Limit', 'I'],
        63: ['Login-LAT-Port', 'S'],
        76: ['Prompt', 'I'],
        79: ['EAP-Message', 'S'],
        80: ['Message-Authenticator', 'S'],
    }

    def __init__(self, packet_type, authenticator):
        """

        :param packet_type: the RADIUS packet type
        :type packet_type: int
        :param authenticator: the RADIUS packet authenicator
        :type authenticator: bytes
        """
        self.attributes = {}

        self.packet_type = packet_type
        self.authenticator = authenticator

    def get_raw_attribute(self, t):
        """
        Get the raw value attribute for the provided type.

        :param t: attribute type
        :type t: int
        :return: the raw attribute values
        :rtype: bytes
        :raise ValueError: if the attribute type doesn't exist
        """
        if t in self.attributes:
            return self.attributes[t]

        raise ValueError(f'Attribute {t} doesn\'t exist')

    def set_attribute(self, t, value):
        """
        Set the attribute.

        The attribute is encoded according to ATTRIBUTE_INFO.

        For one attribute type, only one value can be stored expect the attribute type 26 which is vender specifc. For
        this type 26, a array of value can be defined.

        :param t: the attribute type
        :type t: int
        :param value: the value
        """
        temp = None

        if t in RADIUSPacket.ATTRIBUTES_INFO:
            attr_type = RADIUSPacket.ATTRIBUTES_INFO[t][1]

            if attr_type == 'T' or attr_type == 'S':
                # Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
                if isinstance(value, str):
                    value = value.encode('utf8')
                temp = struct.pack('B', t) + struct.pack('B', 2 + len(value)) + value
            elif attr_type == 'A':
                # Address, 32 bit value, most significant octet first
                ip = value.split('.')
                temp = struct.pack('B', t) + struct.pack('B', 6) + struct.pack('B', int(ip[0])) + \
                       struct.pack('B', int(ip[1])) + struct.pack('B', int(ip[2])) + struct.pack('B', int(ip[3]))
            elif attr_type == 'I':
                # Integer, 32 bit unsigned value, most significant octet first.
                temp = struct.pack('B', t) + struct.pack('B', 6) + struct.pack('>I', value)
            elif attr_type == 'D':
                # Time, 32 bit unsigned value, most significant octet first -- seconds since 00:00:00 UTC,
                # January 1, 1970. (not used in this RFC)
                pass

        if not temp:
            raise ValueError(f'Type {t} with value {value} cannot be set as attribute')

        self.set_raw_attribute(t, temp)

    def set_raw_attribute(self, t, encoded_value):
        """
        Set the attribute with the raw value directly.

        :param t: the attribute type
        :type t: int
        :param encoded_value: the raw value
        :type encoded_value: bytes
        """

        # The type 26 is vendor specific and can be used to store more than one value
        if t == 26:
            self.attributes.setdefault(t, []).append(encoded_value)
        else:
            self.attributes[t] = encoded_value

    def set_include_message_authenticator(self):
        """
        Enable the message authenticator attribute.

        This attribute is used to store the authenticator computed of all the packet, see generate_packet(). For now,
        a 16 nul bytes are used to reserve the space.
        """
        self.set_attribute(80, b'\x00' * 16)

    def generate_packet(self, identifier, secret=None):
        """
        Generate the packet bytes with the identifier.

        The packet is structured like this :
            - the packet type on 1 byte
            - the identifier on 1 byte
            - the length on 2 bytes, big-endian
            - the authenticator on 16 bytes
            - all attributes

        If the packet have the attribute type 80 (see set_include_message_authenticator()), the secret must be defined.
        The value of this attribute is replaced by the message authenticator code which is computed. It's the HMAC-MD5
        of all the packet data (excepting the value of this attribute, logic) with the secret provided.

        :param identifier: the identifier
        :type identifier: int
        :param secret: the secret
        :type secret: bytes
        :return: the packet bytes
        :rtype bytes
        :raise ValueError
        """
        attr_content = b''
        has_authenticator = False
        authenticator_offset = None

        # We loop on each attribute to create attr_content
        for t in self.attributes:
            attr = self.attributes[t]

            if isinstance(attr, list):
                # For list (like the attribute type 26), we merge all
                attr_content += b''.join(attr)
            else:
                if attr[0] == 80:
                    # The attribute type 80 is the message authenticator
                    has_authenticator = True

                    # We save the offset of the value in attr_content because we're going to need it to replace the
                    # current value (16 nul bytes) with the computed value
                    authenticator_offset = len(attr_content) + 2

                attr_content += attr

        # The packet length is 4 + the authenticator length + all attributes data
        packet_len = 4
        packet_len += len(self.authenticator)
        packet_len += len(attr_content)

        packet_data = struct.pack('B', self.packet_type) + \
                      struct.pack('B', identifier) + \
                      struct.pack('>H', packet_len) + \
                      self.authenticator + \
                      attr_content

        if has_authenticator:
            if not secret:
                raise ValueError('Secret must be defined if has_authenticator is set')

            # Compute
            h = HMAC.new(secret, digestmod=MD5)
            h.update(packet_data)

            authenticator_offset += 20  # size of radius packet + next identifier + packent length
            message_authenticator = h.digest()

            # Replace the value in the packet data
            packet_data = packet_data[:authenticator_offset] + \
                          message_authenticator + \
                          packet_data[authenticator_offset + len(message_authenticator):]

        return packet_data

    @staticmethod
    def parse_packet(packet_data, request_authenticator, secret):
        """
        Create a RADIUS packet from the bytes provided.

        See generate_packet() for the packet structure.

        :param b: packet data
        :type b: bytes
        :return: the RADIUSPacket
        :rtype: RADIUSPacket
        :raise ValueError: if the bytes is malformed
        """

        if len(packet_data) < 20:
            raise ValueError('Packet is too small')

        type = struct.unpack('B', packet_data[0:1])[0]
        identifier = struct.unpack('B', packet_data[1:2])[0]
        length = struct.unpack('>H', packet_data[2:4])[0]
        authenticator = packet_data[4:20]

        if length != len(packet_data):
            raise ValueError('Packet lenght is incorrect')

        # Compute the check
        md5_check_ctx = hashlib.md5()
        md5_check_ctx.update(packet_data[0:4])
        md5_check_ctx.update(request_authenticator)
        md5_check_ctx.update(packet_data[20:])
        md5_check_ctx.update(secret)

        if md5_check_ctx.digest() != authenticator:
            raise ValueError('Auth check failed')

        radius_packet = RADIUSPacket(type, authenticator)

        current_offset = 20

        # Read each attribute and add them in the packet
        while (current_offset + 2) < length:
            attr_type = struct.unpack('B', packet_data[current_offset:current_offset + 1])[0]
            attr_length = struct.unpack('B', packet_data[current_offset + 1:current_offset + 2])[0]

            if current_offset + attr_length > length:
                raise ValueError('Attribute length is malformed')

            radius_packet.set_raw_attribute(attr_type, packet_data[current_offset:current_offset + attr_length])

            current_offset += attr_length

        return radius_packet


class RADIUS:
    """
    RADIUS client for MSCHAPv2/EAP-MSCHAPv2 authentification
    """

    def __init__(self, host, shared_secret, nas_ip, nas_identifier, port=1812, timeout=5, eap=True):
        """
        
        :param host: the RADIUS host
        :type host: str
        :param shared_secret: the RADIUS share secret
        :type shared_secret: str
        :param nas_ip: the NAS IP address
        :type nas_ip: str
        :param nas_identifier: the NAS identifier
        :type nas_identifier: str
        :param port: the RADIUS port
        :type port: int
        :param timeout: the server timeout in seconds. Default: 5
        :type timeout: int
        :param eap: Whether to use EAP or legacy MSCHAPv2. Default: True
        :type eap: bool
        """

        self.server = host
        self.secret = shared_secret.encode('utf8')
        self.timeout = timeout
        self.port = port

        self.nas_ip_address = nas_ip
        self.nas_identifier = nas_identifier

        self.authenticator = None
        self.identifier = 0
        self.eap = eap

    def is_credential_valid(self, username, password, fail_silently=False):
        """
        Checks if the provided username and password are valid.

        :param username: the username
        :type username: str
        :param password: the password
        :type password: str
        :type fail_silently: raise exception or juste False
        :type fail_silently: bool
        :return: True or False
        :rtype: bool
        """

        try:
            if self.eap:
                return self._access_request_eap_mschapv2(username.encode('utf8'), password)
            return self._access_request_mschapv2(username.encode('utf8'), password)
        except (ValueError, socket.error) as e:
            if fail_silently:
                return False
            else:
                raise e

    def _access_request_mschapv2(self, username, password):
        """
        Attempt to achieve user authentication with the provided username and password in legacy MSCHAPv2.

        RADIUS MSCHAPv2 Process:
            > RADIUS ACCESS_REQUEST with MSCHAP identity packet
            < ACCESS_ACCEPT with MSCHAP success packet

        :param username: the username
        :type username: bytes
        :param password: the password
        :type password: str
        :return: True or False
        :rtype: bool
        :raise socket.error or ValueError
        """

        # Generate the request authenticator
        self.authenticator = self._generate_random_bytes(16)

        # Stage one :
        #   The client sends the first ACCESS REQUEST with MSCHAP identity
        #
        # The packet contains :
        #   - the NAS IP address if defined
        #   - the NAS identifier if defined
        #   - the username (attribute type 1)
        #   - The attribute type 6 with value 1 for the login phase
        #   - the vendor-specific (attribute type 26) containing MSCHAP challenge
        #   - the vendor-specific (attribute type 26) containing MSCHAP challenge response
        #   - the message authenticator
        #
        packet_to_send = RADIUSPacket(RADIUSPacket.TYPE_ACCESS_REQUEST, self.authenticator)

        if self.nas_ip_address:
            packet_to_send.set_attribute(4, self.nas_ip_address)

        if self.nas_identifier:
            packet_to_send.set_attribute(32, self.nas_identifier)

        # The username is added
        packet_to_send.set_attribute(1, username)
        packet_to_send.set_attribute(6, 1)

        # Generate a new challenges
        auth_challenge = self._generate_random_bytes(16)
        peer_challenge = self._generate_random_bytes(16)
        challengePacket = VendorSpecificPacket(VendorSpecificPacket.VENDOR_MICROSOFT, VendorSpecificPacket.TYPE_MSCHAP_CHALLENGE, auth_challenge)
        packet_to_send.set_attribute(26, challengePacket.__bytes__())

        # calculate response
        mschapv2_crypto = MSCHAPv2Crypto(0,
                                         auth_challenge,
                                         peer_challenge,
                                         username,
                                         password)
        mschapResponse =  MSCHAPv2Response(peer_challenge, mschapv2_crypto.challenge_response())
        responsePacket = VendorSpecificPacket(VendorSpecificPacket.VENDOR_MICROSOFT, VendorSpecificPacket.TYPE_MSCHAP_RESPONSE, mschapResponse.__bytes__())
        packet_to_send.set_attribute(26, responsePacket.__bytes__())

        # Final response of the server
        packet_to_send.set_include_message_authenticator()
        response_packet = self._send_and_read(packet_to_send)
        return response_packet.packet_type == RADIUSPacket.TYPE_ACCESS_ACCEPT

    def _access_request_eap_mschapv2(self, username, password):
        """
        Attempt to achieve user authentication with the provided username and password in EAP-MSCHAPv2.

        RADIUS EAP MSCHAPv2 Process:
            > RADIUS ACCESS_REQUEST with EAP identity packet
            < ACCESS_CHALLENGE with MSCHAP challenge encapsulated in EAP request

            CHAP packet contains auth_challenge value
            Calculate response for the challenge

            > ACCESS_REQUEST with MSCHAP challenge response, peer_challenge
            < ACCESS_CHALLENGE with MSCHAP success or failure in EAP packet.

            > ACCESS_CHALLENGE with EAP success packet
            < ACCESS_ACCEPT with EAP success packet

        :param username: the username
        :type username: bytes
        :param password: the password
        :type password: str
        :return: True or False
        :rtype: bool
        :raise socket.error or ValueError
        """

        # Generate the request authenticator
        self.authenticator = self._generate_random_bytes(16)

        # Stage one :
        #   The client sends the first ACCESS REQUEST with EAP identity
        #   The server must respond with a ACCESS CHALLENGE containing the EAP-MSCHAPv2 challenge.
        #
        # Note that the server respond also with a state in the attribute 24. We must send it back in the stage two.
        #
        # The packet contains :
        #   - the NAS IP address if defined
        #   - the NAS identifier if defined
        #   - the username (attribute type 1)
        #   - the EAP (attribute type 79) containing only the username
        #   - the message authenticator
        #   - The attribute type 6 with value 1 for the login phase
        #
        packet_to_send = RADIUSPacket(RADIUSPacket.TYPE_ACCESS_REQUEST, self.authenticator)

        if self.nas_ip_address:
            packet_to_send.set_attribute(4, self.nas_ip_address)

        if self.nas_identifier:
            packet_to_send.set_attribute(32, self.nas_identifier)

        # The username is added
        packet_to_send.set_attribute(1, username)
        packet_to_send.set_attribute(79, EAPPacket.identity(username))
        packet_to_send.set_include_message_authenticator()
        packet_to_send.set_attribute(6, 1)

        response_packet = self._send_and_read(packet_to_send)

        # Stage two :
        #   The client compute the response for the challenge and send it.
        #   The server lyst respond with a EAP-MSCHAPv2 opcode set to Success
        #
        # The packet contains :
        #   - the username (attribute type 1)
        #   - the EAP (attribute type 79) containing the MSCHAPv2 packet :
        #       * Type: EAP-MS-AUTH (26)
        #       * OpCode: Response (2)
        #       * Peer-challenge: a new random challenge
        #       * NT-Response: the computed response for the server's challenge
        #       * Name: the username
        #   - the message authenticator
        #   - the state from the previous response

        response_eap = EAPPacket.from_bytes(response_packet.get_raw_attribute(79)[2:])
        if response_eap.code != EAPPacket.CODE_REQUEST:
            raise ValueError('Stage 1 : the server doesn\'t respond as expected')

        state = response_packet.get_raw_attribute(24)

        if response_eap.type == EAPPacket.TYPE_MD5_CHALLENGE:
            state = response_packet.get_raw_attribute(24)
            packet_to_send = RADIUSPacket(RADIUSPacket.TYPE_ACCESS_REQUEST, self.authenticator)
            packet_to_send.set_attribute(1, username)
            packet_to_send.set_attribute(79, EAPPacket.legacyNak(response_eap.id))
            packet_to_send.set_raw_attribute(24, state)
            packet_to_send.set_include_message_authenticator()
            
            response_packet = self._send_and_read(packet_to_send)
            
            state = response_packet.get_raw_attribute(24)

            response_eap = EAPPacket.from_bytes(response_packet.get_raw_attribute(79)[2:])
            if response_eap.code != EAPPacket.CODE_REQUEST:
                raise ValueError('Stage 1b : the server doesn\'t respond as expected')

        if response_eap.type != EAPPacket.TYPE_EAP_MS_AUTH:
            raise ValueError('Stage 1b : the server doesn\'t respond as expected')

        response_eap_mschap2 = MSCHAPv2Packet.from_bytes(response_eap.data)

        if response_eap_mschap2.opcode != MSCHAPv2Packet.OPCODE_CHALLENGE:
            raise ValueError('Stage 1 : the server doesn\'t respond as expected')

        # Generate a new peer challenge
        peer_challenge = self._generate_random_bytes(16)

        mschapv2_crypto = MSCHAPv2Crypto(response_eap_mschap2.ms_chap_id,
                                         response_eap_mschap2.challenge,
                                         peer_challenge,
                                         username,
                                         password)

        response_mschapv2 = MSCHAPv2Packet(MSCHAPv2Packet.OPCODE_RESPONSE)
        response_mschapv2.ms_chap_id = response_eap_mschap2.ms_chap_id
        response_mschapv2.challenge = peer_challenge
        response_mschapv2.response = mschapv2_crypto.challenge_response()
        response_mschapv2.name = username

        packet_to_send = RADIUSPacket(RADIUSPacket.TYPE_ACCESS_REQUEST, self.authenticator)

        packet_to_send.set_attribute(1, username)
        packet_to_send.set_attribute(79, EAPPacket.mschapv2(response_mschapv2, response_eap_mschap2.ms_chap_id))
        packet_to_send.set_include_message_authenticator()
        packet_to_send.set_raw_attribute(24, state)

        response_packet = self._send_and_read(packet_to_send)

        # Stage three :
        #   The client sends a EAP-MSCHAPv2 with code response and opcode Success
        #   The servers sends back a EAP with code Success
        #
        # The packet contains :
        #   - the username (attribute type 1)
        #   - the EAP (attribute type 79) containing only the MSCHAPv2 packet :
        #       * OpCde: Success (3)
        #   - the message authenticator
        #   - the state from the previous response

        response_eap = EAPPacket.from_bytes(response_packet.get_raw_attribute(79)[2:])

        if response_eap.code != EAPPacket.CODE_REQUEST:
            raise ValueError('Stage 2 : the server doesn\'t respond as expected')

        response_eap_mschap2 = MSCHAPv2Packet.from_bytes(response_eap.data)

        if response_eap_mschap2.opcode != MSCHAPv2Packet.OPCODE_SUCCESS:
            raise ValueError('Stage 2 : the server doesn\'t respond as expected')

        state = response_packet.get_raw_attribute(24)

        mschapv2_response = MSCHAPv2Packet(MSCHAPv2Packet.OPCODE_SUCCESS)

        packet_to_send = RADIUSPacket(RADIUSPacket.TYPE_ACCESS_REQUEST, self.authenticator)

        packet_to_send.set_attribute(1, username)
        packet_to_send.set_attribute(79, EAPPacket.mschapv2(mschapv2_response, response_eap_mschap2.ms_chap_id + 1))
        packet_to_send.set_include_message_authenticator()
        packet_to_send.set_raw_attribute(24, state)

        response_packet = self._send_and_read(packet_to_send)

        # Final response of the server
        response_eap = EAPPacket.from_bytes(response_packet.get_raw_attribute(79)[2:])

        return response_packet.packet_type == RADIUSPacket.TYPE_ACCESS_ACCEPT and \
               response_eap.code == EAPPacket.CODE_SUCCESS

    def _send_and_read(self, radius_packet):
        """
        Send the RADIUS packet, read the response from the server and convert it into a RADIUS packet.

        :param radius_packet: the packet to send
        :type radius_packet: RADIUSPacket
        :return: the RADIUSPacket from the server
        :rtype: RADIUSPacket
        """
        packet_data = radius_packet.generate_packet(self._get_next_identifier(),
                                                    self.secret)

        sock = self._send_radius_request(packet_data)
        resp = self._read_radius_response(sock)
        sock.close()

        resp_packet = RADIUSPacket.parse_packet(resp, self.authenticator, self.secret)
        return resp_packet

    def _get_next_identifier(self):
        """
        Get the next identifier to use.

        :return: the next identifier
        :rtype: int
        """
        self.identifier = (self.identifier + 1) % 256
        return self.identifier

    def _send_radius_request(self, packet_data):
        """
        Send the RADIUS packet data.

        :param packet_data: the packet data:
        :type packet_data: bytes
        :return: the socket
        :rtype: socket.socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        sock.sendto(packet_data, (self.server, self.port))

        return sock

    def _read_radius_response(self, sock):
        """
        Read the RADIUS response packet data.

        :param sock: the socket
        :type sock: socket.socket
        :return: the response bytes
        :rtype bytes
        """
        return sock.recv(4096)

    @staticmethod
    def _generate_random_bytes(size=8):
        """
        Generate random <size> bytes.

        :param size: the number of bytes
        :type size: int
        :return: the bytes
        :rtype: bytes
        """
        b = bytearray()

        for i in range(0, size):
            b += struct.pack('B', random.randint(0, 255))

        return b
