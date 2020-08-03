import rlp
from rlp.sedes import big_endian_int, BigEndianInt, Binary, binary, CountableList
from rlp.sedes.serializable import Serializable

address = Binary.fixed_length(20, allow_empty=True)
hash32 = Binary.fixed_length(32)


class Transaction(Serializable):
    fields = [
        ('nonce', big_endian_int),
        ('gas_price', big_endian_int),
        ('gas', big_endian_int),
        ('to', address),
        ('value', big_endian_int),
        ('data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int),
    ]

    def __init__(self, nonce, gas_price, gas, to, value, data, v=0, r=0, s=0, **kwargs):
        super().__init__(nonce, gas_price, gas, to, value, data, v, r, s, **kwargs)