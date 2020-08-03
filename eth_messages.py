# from https://github.com/ethereum/eth-account/blob/master/eth_account/messages.py
# commit: https://github.com/ethereum/eth-account/blob/00e7b10005c5fa7090086fcef37a76296c524e17/eth_account/messages.py

# from collections.abc import (
    # Mapping,
# )
import json
from typing import (
    NamedTuple,
    #Union,
)

from eth_typing import (
#    Address,
    Hash32,
)
from eth_utils.curried import keccak, to_bytes
from hexbytes import (
    HexBytes,
)

# from eth_account._utils.structured_data.hashing import (
    # hash_domain,
    # hash_message as hash_eip712_message,
    # load_and_validate_structured_message,
# )
# from eth_account._utils.validation import (
    # is_valid_address,
# )

#text_to_bytes = text_if_str(to_bytes)

# watch for updates to signature format
class SignableMessage(NamedTuple):
    """
    These are the components of an EIP-191_ signable message. Other message formats
    can be encoded into this format for easy signing. This data structure doesn't need to
    know about the original message format.
    In typical usage, you should never need to create these by hand. Instead, use
    one of the available encode_* methods in this module, like:
        - :meth:`encode_structured_data`
        - :meth:`encode_intended_validator`
        - :meth:`encode_structured_data`
    .. _EIP-191: https://eips.ethereum.org/EIPS/eip-191
    """
    version: bytes  # must be length 1
    header: bytes  # aka "version specific data"
    body: bytes  # aka "data to sign"


def _hash_eip191_message(signable_message: SignableMessage) -> Hash32:
    version = signable_message.version
    if len(version) != 1:
        raise ValidationError(
            "The supplied message version is {version!r}. "
            "The EIP-191 signable message standard only supports one-byte versions."
        )

    joined = b'\x19' + version + signable_message.header + signable_message.body
    return Hash32(keccak(joined))

def encode_defunct(
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None) -> SignableMessage:
    r"""
    Encode a message for signing, using an old, unrecommended approach.
    Only use this method if you must have compatibility with
    :meth:`w3.eth.sign() <web3.eth.Eth.sign>`.
    EIP-191 defines this as "version ``E``".
    .. NOTE: This standard includes the number of bytes in the message as a part of the header.
        Awkwardly, the number of bytes in the message is encoded in decimal ascii.
        So if the message is 'abcde', then the length is encoded as the ascii
        character '5'. This is one of the reasons that this message format is not preferred.
        There is ambiguity when the message '00' is encoded, for example.
    Supply exactly one of the three arguments: bytes, a hex string, or a unicode string.
    :param primitive: the binary message to be signed
    :type primitive: bytes or int
    :param str hexstr: the message encoded as hex
    :param str text: the message as a series of unicode characters (a normal Py3 str)
    :returns: The EIP-191 encoded message, ready for signing
    .. doctest:: python
        >>> from eth_account.messages import encode_defunct
        >>> from eth_utils.curried import to_hex, to_bytes
        >>> message_text = "I♥SF"
        >>> encode_defunct(text=message_text)
        SignableMessage(version=b'E', header=b'thereum Signed Message:\n6', body=b'I\xe2\x99\xa5SF')
        These four also produce the same hash:
        >>> encode_defunct(to_bytes(text=message_text))
        SignableMessage(version=b'E', header=b'thereum Signed Message:\n6', body=b'I\xe2\x99\xa5SF')
        >>> encode_defunct(bytes(message_text, encoding='utf-8'))
        SignableMessage(version=b'E', header=b'thereum Signed Message:\n6', body=b'I\xe2\x99\xa5SF')
        >>> to_hex(text=message_text)
        '0x49e299a55346'
        >>> encode_defunct(hexstr='0x49e299a55346')
        SignableMessage(version=b'E', header=b'thereum Signed Message:\n6', body=b'I\xe2\x99\xa5SF')
        >>> encode_defunct(0x49e299a55346)
        SignableMessage(version=b'E', header=b'thereum Signed Message:\n6', body=b'I\xe2\x99\xa5SF')
    """
    message_bytes = to_bytes(primitive, hexstr=hexstr, text=text)
    msg_length = str(len(message_bytes)).encode('utf-8')

    # Encoding version E defined by EIP-191
    return SignableMessage(
        b'E',
        b'thereum Signed Message:\n' + msg_length,
        message_bytes,
    )


def defunct_hash_message(
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None) -> HexBytes:
    """
    Convert the provided message into a message hash, to be signed.
    .. CAUTION:: Intented for use with the deprecated :meth:`eth_account.account.Account.signHash`.
        This is for backwards compatibility only. All new implementations
        should use :meth:`encode_defunct` instead.
    :param primitive: the binary message to be signed
    :type primitive: bytes or int
    :param str hexstr: the message encoded as hex
    :param str text: the message as a series of unicode characters (a normal Py3 str)
    :returns: The hash of the message, after adding the prefix
    """
    signable = encode_defunct(primitive, hexstr=hexstr, text=text)
    hashed = _hash_eip191_message(signable)
    return HexBytes(hashed)