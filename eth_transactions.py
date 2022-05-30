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

# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md
# 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s])
# https://github.com/ethereum/py-evm/blob/master/eth/vm/forks/london/transactions.py
class AccountAccesses(Serializable):
    fields = [
        ('account', Binary.fixed_length(20, allow_empty=True)),
        ('storage_keys', CountableList(BigEndianInt(32))),
    ]

class TransactionEIP1559(Serializable):
    fields = [
        ("chain_id", big_endian_int),
        ("nonce", big_endian_int),
        ("max_priority_fee_per_gas", big_endian_int),
        ("max_fee_per_gas", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
        ("access_list", CountableList(AccountAccesses)),
    ]
