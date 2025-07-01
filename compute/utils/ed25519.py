import io
import paramiko

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def generate_ssh_keypair():
    """
    Generate new (random) ED25519 keypair for ephemeral authentication
    """
    new_keypair = Ed25519PrivateKey.generate()
    p_key = io.StringIO(new_keypair.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()).decode())
    return paramiko.Ed25519Key.from_private_key(p_key)
    # getting pubkey from this object is tricky but pk.get_base64() should get most of it


def get_ssh_public_key(pkey: paramiko.Ed25519Key):
    return f"ssh-ed25519 {pkey.get_base64()} validator@sn27"  # TODO perhaps better identifier
