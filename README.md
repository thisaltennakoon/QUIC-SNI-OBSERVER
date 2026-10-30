# QUIC SNI Observer

QUIC encrypts almost everything, yet anyone on the network path can still read the
website name in a client's first packet. This tool shows how. It decrypts a QUIC
version 1 client Initial packet using only public values, then prints the server name
(SNI) from the TLS ClientHello inside it. It follows the steps defined in RFC 9001,
the same steps any on-path observer, such as the Great Firewall of China, has to follow.

## Run it with Docker

```sh
docker run --rm ghcr.io/thisaltennakoon/quic-sni-observer
```

Expected output:

```
packet number: 2
server name: example.com
```

With no input, the tool reads `client_initial.txt`: the protected client Initial packet
printed in RFC 9001.

## A second sample

`client_initial_wikipedia.txt` holds a client Initial for `www.wikipedia.org`. It was
generated offline with the open-source QUIC library aioquic (version 1.7.0); no traffic
was sent. Download the file, then run:

```sh
docker run --rm -i ghcr.io/thisaltennakoon/quic-sni-observer - < client_initial_wikipedia.txt
```

On Windows PowerShell:

```powershell
Get-Content client_initial_wikipedia.txt | docker run --rm -i ghcr.io/thisaltennakoon/quic-sni-observer -
```

Expected output:

```
packet number: 0
server name: www.wikipedia.org
```

## Try your own packet

The packet is given as hex digits. Spaces and line breaks are ignored.

| Input | Command |
| --- | --- |
| A file (macOS, Linux, Git Bash) | `docker run --rm -i ghcr.io/thisaltennakoon/quic-sni-observer - < my_packet.txt` |
| A file (Windows PowerShell) | `Get-Content my_packet.txt \| docker run --rm -i ghcr.io/thisaltennakoon/quic-sni-observer -` |
| A value | `docker run --rm ghcr.io/thisaltennakoon/quic-sni-observer --hex "c000000001..."` |

## Credits

The `QUICCrypto` class in `read_sni.py` is adapted from `utils/quic-packet-builder/crypto.py`
in the artifact repository of A. Zohaib et al., *Exposing and Circumventing SNI-based QUIC
Censorship of the Great Firewall of China* (USENIX Security 2025):
<https://github.com/gfw-report/usenixsecurity25-quic-sni>. The rest of the script follows
RFC 9000 and RFC 9001.

`client_initial.txt` is the example client Initial packet from RFC 9001, Appendix A.2.
`client_initial_wikipedia.txt` was generated offline with aioquic.
