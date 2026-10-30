# read_sni.py: play the on-path observer. Decrypt a QUIC v1 client Initial
# using only public values, then print the server name (SNI).
#
# The QUICCrypto class is adapted from utils/quic-packet-builder/crypto.py in
# the artifact repository of Zohaib et al., "Exposing and Circumventing
# SNI-based QUIC Censorship of the Great Firewall of China" (USENIX Security 2025):
# https://github.com/gfw-report/usenixsecurity25-quic-sni (commit 1e9eeb5).
# Changes: client keys only; the original encrypts packets, so decrypt_packet
# runs its AES-GCM step in reverse; header_protect also removes protection,
# because XOR with the same mask undoes itself.
#
# Usage: python3 read_sni.py              packet from client_initial.txt
#        python3 read_sni.py FILE         packet from FILE (hex)
#        python3 read_sni.py -            packet from standard input (hex)
#        python3 read_sni.py --hex HEX    packet given directly as hex
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class QUICCrypto:
    # Initial salt for QUIC version 1 (RFC 9001 Section 5.2)
    INITIAL_SALTS = {1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")}

    def __init__(self, dcid, version=1):
        initial_secret = self._hkdf_extract(self.INITIAL_SALTS[version], dcid)
        client_initial_secret = self._hkdf_expand_label(initial_secret, b"client in", b"", 32)
        self.client_key = self._hkdf_expand_label(client_initial_secret, b"quic key", b"", 16)
        self.client_iv = self._hkdf_expand_label(client_initial_secret, b"quic iv", b"", 12)
        self.client_hp_key = self._hkdf_expand_label(client_initial_secret, b"quic hp", b"", 16)

    def _hkdf_extract(self, salt, ikm):
        # HKDF-Extract is HMAC-SHA256 keyed with the salt
        hk = hmac.HMAC(salt, hashes.SHA256())
        hk.update(ikm)
        return hk.finalize()

    def _hkdf_expand_label(self, secret, label, context, length):
        # TLS 1.3 HKDF-Expand-Label: HkdfLabel = length + "tls13 " label + context
        full_label = b"tls13 " + label
        hkdf_label = (length.to_bytes(2, "big") +
                      bytes([len(full_label)]) + full_label +
                      bytes([len(context)]) + context)
        return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label).derive(secret)

    def _build_nonce(self, iv, pn):
        # Nonce = IV XOR the packet number, right-aligned in 12 bytes
        pn_bytes = pn.to_bytes(4, "big")
        padded_pn = (b"\x00" * (len(iv) - len(pn_bytes))) + pn_bytes
        return bytes(a ^ b for a, b in zip(iv, padded_pn))

    def header_protect(self, sample, first_byte, pn_bytes):
        # Mask = AES-ECB(hp key, sample); long header: low 4 bits of byte 0
        cipher = Cipher(algorithms.AES(self.client_hp_key), modes.ECB()).encryptor()
        mask = cipher.update(sample) + cipher.finalize()
        first_byte_masked = first_byte ^ (mask[0] & 0x0f)
        masked_pn = bytes(p ^ m for p, m in zip(pn_bytes, mask[1:1 + len(pn_bytes)]))
        return first_byte_masked, masked_pn

    def decrypt_packet(self, pn, header, ciphertext_with_tag):
        # AES-128-GCM; the header is the associated data (RFC 9001 Sec. 5.3)
        nonce = self._build_nonce(self.client_iv, pn)
        ciphertext, tag = ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
        decryptor = Cipher(algorithms.AES(self.client_key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        return decryptor.update(ciphertext) + decryptor.finalize()

def varint(buf, i):                                # QUIC variable-length integer
    size = 1 << (buf[i] >> 6)
    value = buf[i] & 0x3F
    for b in buf[i + 1:i + size]: value = (value << 8) | b
    return value, i + size

# Step 0: read the captured packet (hex; spaces and line breaks are fine)
args = sys.argv[1:]
if not args:
    text = Path(__file__).with_name("client_initial.txt").read_text()
elif args[0] == "--hex":
    text = " ".join(args[1:])
elif args[0] == "-":
    text = sys.stdin.read()
else:
    text = Path(args[0]).read_text()
pkt = bytes.fromhex(text)
if pkt[0] & 0xF0 != 0xC0 or pkt[1:5] != b"\x00\x00\x00\x01":
    sys.exit("not a QUIC version 1 Initial packet")

# Step 1: parse the visible long header (RFC 9000 Sec. 17.2.2)
dcid = pkt[6:6 + pkt[5]]                           # byte 5 = DCID length
i = 6 + len(dcid)
i += 1 + pkt[i]                                    # skip SCID length + SCID
token_len, i = varint(pkt, i); i += token_len      # skip Token Length + Token
length, pn_offset = varint(pkt, i)                 # Length field; PN starts next

# Step 2: derive the client's Initial keys from the salt and the DCID
crypto = QUICCrypto(dcid)

# Step 3: remove header protection (RFC 9001 Sec. 5.4)
sample = pkt[pn_offset + 4:pn_offset + 20]
first_byte, pn_field = crypto.header_protect(sample, pkt[0], pkt[pn_offset:pn_offset + 4])
pn_len = (first_byte & 0x03) + 1
pn = int.from_bytes(pn_field[:pn_len], "big")

# Step 4: remove packet protection
header = bytes([first_byte]) + pkt[1:pn_offset] + pn_field[:pn_len]
payload = crypto.decrypt_packet(pn, header, pkt[pn_offset + pn_len:pn_offset + length])

# Step 5: the first frame is a CRYPTO frame (type 0x06) carrying the ClientHello
if payload[0] != 0x06:
    sys.exit("first frame is not a CRYPTO frame; this simple script stops here")
_, j = varint(payload, 1)                          # CRYPTO offset
crypto_len, j = varint(payload, j)
ch = payload[j:j + crypto_len]
p = 4 + 2 + 32                                     # handshake header, version, random
p += 1 + ch[p]                                     # session ID
p += 2 + int.from_bytes(ch[p:p + 2], "big")        # cipher suites
p += 1 + ch[p]                                     # compression methods
end = p + 2 + int.from_bytes(ch[p:p + 2], "big"); p += 2
print("packet number:", pn)
while p < end:                                     # walk the extensions
    ext_type = int.from_bytes(ch[p:p + 2], "big")
    ext_len = int.from_bytes(ch[p + 2:p + 4], "big")
    if ext_type == 0x0000:                         # server_name
        name_len = int.from_bytes(ch[p + 7:p + 9], "big")
        print("server name:", ch[p + 9:p + 9 + name_len].decode())
        break
    p += 4 + ext_len
else:
    print("server name: none (no server_name extension)")
