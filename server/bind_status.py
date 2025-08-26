# MS-RPCE 2.2.4.12 NDR Transfer Syntax Identifier
#MSRPC_STANDARD_NDR_SYNTAX = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0')
# 20-байтовые «сигнатуры» transfer syntax (UUID + major + minor LE)
from impacket.uuid import uuidtup_to_bin

# Transfer Syntaxes (GUID + version)
NDR32_TUP = ('8a885d04-1ceb-11c9-9fe8-08002b104860', "2.0")
NDR64_TUP = ('71710533-beba-4937-8319-b5dbef9ccc36', "1.0")
FEAT_TUP = ('6cb71c2c-9812-4540-0300-000000000000', "1.0")

DCERPC_PTYPE_BIND = 11
DCERPC_PTYPE_BIND_ACK = 12
PFC_FIRST = 0x01
PFC_LAST  = 0x02
# Initialize transfer syntaxes with error handling
NDR32_BIN = uuidtup_to_bin(NDR32_TUP)
NDR64_BIN = uuidtup_to_bin(NDR64_TUP)
FEAT_BIN  = uuidtup_to_bin(FEAT_TUP)