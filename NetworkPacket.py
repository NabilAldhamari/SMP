import fcntl, socket
from struct import *
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes

class NetworkPacket:
    class IPHeader:
        def __init__(self, source_ip, dest_ip):
            if not source_ip or not dest_ip:
                raise Exception("IP Header needs a source and destination ip address")
                # TODO
                # Check the availabilty of source and dest ips.

            self.ip_ihl      = 5
            self.ip_ver      = 4
            self.ip_tos      = 0
            self.ip_tot_len  = 0	
            self.ip_id       = 1	
            self.ip_frag_off = 0
            self.ip_ttl      = 255
            self.ip_proto    = 99   # Private Encryption Scheme (custom proto)
            self.ip_check    = 0	# Auto checksum by kernel
            self.ip_saddr    = socket.inet_aton(source_ip)
            self.ip_daddr    = socket.inet_aton(dest_ip)
            self.ip_ihl_ver  = None # Calculated later
            self.ip_header   = None # To be constructed

        def enableV6(self):
            self.ip_ver = 6

        def construct(self):
            self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
            self.ip_header  = pack('!BBHHHBBH4s4s' , self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_frag_off, self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)

            return self.ip_header

    class MPHeader:
        def __init__(self, data=b""):
            self.MP_FORMAT      = '!HHLLHHHx'
            self.options        = 0
            self.fragmentation  = 0
            self.sequence       = 100
            self.nextSequence   = 0
            self.flags          = 0
            self.messageType    = 1
            self.dest_port      = 0
            self.data           = data
            self.mp_header      = None
            self.payload        = None

        def construct(self):
            self.mp_header = pack(self.MP_FORMAT, self.options, self.fragmentation, self.sequence, self.nextSequence, self.flags, self.messageType, self.dest_port)
            return self.mp_header + self.data

        def loadPacket(self, packet):
            frag = calcsize(self.MP_FORMAT)
            data = packet[frag:]
            MP   = unpack(self.MP_FORMAT, packet[:frag])

            if len(MP) > 0: 
                self.options        = MP[0]
                self.fragmentation  = MP[1]
                self.sequence       = MP[2]
                self.nextSequence   = MP[3]
                self.flags          = MP[4]
                self.messageType    = MP[5]
                self.dest_port      = MP[6]
                self.data           = data
            return MP

        def setOptions(self, value):
            self.options = value
        def getOptions(self):
            return self.options

        def setFragmentation(self, value):
            self.fragmentation = value
        def getFragmentation(self):
            return self.fragmentation

        def setSequence(self, value):
            self.sequence = value
        def getSequence(self):
            return self.sequence
        
        def setNextSequence(self, value):
            self.nextSequence = value
        def getNextSequence(self):
            return self.nextSequence
        
        def setFlags(self, value):
            self.flags = value
        def getFlags(self):
            return self.flags
        
        def setMessageType(self, value):
            self.messageType = value
        def getMessageType(self):
            return self.messageType
        
        def setDestinationPort(self, value):
            self.dest_port = value
        def getDestinationPort(self):
            return self.dest_port

        def setData(self, value):
            self.data = value
        def getData(self):
            return self.data

    class Encryption:
        def __init__(self, hashAlg="SHA-256"):
            self.hashAlg = hashAlg

        def encryptPayload(self, data, publicKey):
            # Generate a random 16 byte session key
            session_key     = get_random_bytes(16)

            # Generate and Encrypt the session key with RSA publicKey
            rsaPubKey       = PKCS1_OAEP.new(publicKey)
            encSessionKey   = rsaPubKey.encrypt(session_key)

            # Encrypt the rest of the data with AES and append
            aesCipher       = AES.new(session_key, AES.MODE_EAX)
            encrypted, tag  = aesCipher.encrypt_and_digest(data)

            return pack('!'+str(publicKey.size_in_bytes())+'s16s16s', encSessionKey, aesCipher.nonce, tag) + encrypted

        def decryptPayload(self, encrypted, privateKey):
            packFormat      = '!'+str(privateKey.size_in_bytes())+'s16s16s'
            frag            = calcsize(packFormat)
            cipherText      = encrypted[frag:]

            arr             = unpack(packFormat, encrypted[:frag])
            encSessionKey   = arr[0]
            nonce           = arr[1]
            tag             = arr[2]

            # Decrypt the session key
            cipher_rsa  = PKCS1_OAEP.new(privateKey)
            sessionKey  = cipher_rsa.decrypt(encSessionKey)

            # Decrypt the data
            cipher_aes = AES.new(sessionKey, AES.MODE_EAX, nonce)
            data       = cipher_aes.decrypt_and_verify(cipherText, tag)

            return data.decode("utf-8")

        def generateKeys(self, keyLength=1024):
            rand = Random.new().read
            key  = RSA.generate(keyLength, rand)
            priv, pub = key, key.publickey()
            return pub, priv
        
        def importKey(self, key):
            return RSA.importKey(key)
