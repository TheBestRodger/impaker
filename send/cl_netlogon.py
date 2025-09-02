from impacket.dcerpc.v5 import epm, lsad, rpcrt, transport, lsat, ndr, nrpc
from impacket.uuid import bin_to_uuidtup
from random import randbytes

authn_level_packet = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
nrpc_uid = nrpc.MSRPC_UUID_NRPC
syntax = rpcrt.DCERPC.NDR64Syntax

# Собственно хост куда мы подключаемся
host="192.168.1.10"

# unc имя домен контроллера к которому мы подключаемся
primary_name = r'\\DCMS.msdomain.nikan'

# Это как бы логин в логике Netlogon используется имя компа который подключается
computer_name = 'NKDC'

# Это паролькоторый мы указывали про создании TDO
tdo_pass='0123456789'

# Это не используется
password=''

# Тут мы даем понять что мы не кто нибудь контролле указанного домена
account_name = 'nkdomain.nikan.'

# Домен к которрому мы подключаемся
domain = 'MSDOMAIN'

# Во такой у нас end point 
# ncacn_np говорит что у нас named pipe
# \PIPE\netlogon название pipe
binding_string_nrpc=rf"ncacn_np:{host}[\PIPE\netlogon]"

#Конектимся к SMB
rpctransport = transport.DCERPCTransportFactory(binding_string_nrpc)
dce = rpctransport.get_dce_rpc()
dce.connect()

# Сообщаем либе что мы пользуем netlogon интерфейс
dce.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=bin_to_uuidtup(syntax))

# Генерим рандомный Challenge
clientchall = randbytes(8)
print("[-] client chall: {}".format("".join((format(x, '02x') for x in clientchall))))
print("[x] Calling NetrServerReqChallenge")

# Обмениваемся раномными челенджами
resp = nrpc.hNetrServerReqChallenge(dce, primary_name, computer_name + '\x00', clientchall)
print("[x] NetrServerReqChallenge ok!")
serverchall = resp["ServerChallenge"]
print("[-] server chall: {}".format("".join((format(x, '02x') for x in serverchall))))

# Вычисляем session Key и client credential
# Тут нам нужен наш tdo_pass
sessionKey = nrpc.ComputeSessionKeyAES(tdo_pass, clientchall, serverchall)
clientcred = nrpc.ComputeNetlogonCredentialAES(clientchall, sessionKey)
print("[-] session Key: {}".format("".join((format(x, '02x') for x in sessionKey))))
print("[-] client credential: {}".format("".join((format(x, '02x') for x in clientcred))))
print("[+] Calling NetrServerAuthenticate3")

# Ну и аутентификация
resp = nrpc.hNetrServerAuthenticate3(dce, primary_name + '\x00', account_name + '\x00', 
                                     nrpc.NETLOGON_SECURE_CHANNEL_TYPE.TrustedDnsDomainSecureChannel, 
                                     computer_name + '\x00', clientcred, 0x613FFFFF)
print("[x] NetrServerAuthenticate3 ok!") 
servercred = resp['ServerCredential']
print("[-] server credential: {}".format("".join((format(x, '02x') for x in servercred))))

# Тут мы переключаемся на защищенный канал. Если этого не сделать то нас NetrLogonGetCapabilities пошлет
dce.set_credentials(computer_name + '$', password, domain)
dce.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
dce.set_auth_level(authn_level_packet)
dce.set_aes(True)
resp = dce.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=bin_to_uuidtup(syntax))
dce.set_session_key(sessionKey)

# Ну и проверям secure channel
auth = nrpc.ComputeNetlogonAuthenticatorAES(clientcred, sessionKey)
print("[-] Netlogon authenticator: {}".format("".join((format(x, '02x') for x in auth['Credential']))))
print('[+] Calling NetrLogonGetCapabilities')
resp = nrpc.hNetrLogonGetCapabilities(dce, primary_name, computer_name, auth)
print("[x] NetrLogonGetCapabilities ok!") 
resp.dump()