
"""
This function is used to parse a binary response from the following cups api call /update-info
doc: https://doc.sm.tc/station/cupsproto.html#http-post-response
"""
def parse_response(data):
    # !! The length fields shall be encoded in little endian. 
    offset = 0  # Byte offset at beginning

    # Read cupsUriLen (1 byte)
    cupsUriLen = data[offset]
    offset += 1

    if cupsUriLen > 0:
        # Read cupsUri (cupsUriLen bytes)
        cupsUri = data[offset:offset + cupsUriLen].decode()
        offset += cupsUriLen
    else:
        cupsUri = ""

    # Read tcUriLen (1 byte)
    tcUriLen = data[offset]
    offset += 1

    if tcUriLen > 0:
        # Read tcUri (tcUriLen bytes)
        tcUri = data[offset:offset + tcUriLen].decode()
        offset += tcUriLen
    else:
        tcUri = ""

    # Read cupsCredLen (2 bytes, little endian)
    cupsCredLen = int.from_bytes(data[offset:offset + 2], byteorder='little')
    offset += 2

    if cupsCredLen > 0:
        # Read cupsCred (cupsCredLen bytes)
        cupsCred = data[offset:offset + cupsCredLen]
        offset += cupsCredLen
    else:
        cupsCred = ""

    # Read tcCredLen (2 bytes, little endian)
    tcCredLen = int.from_bytes(data[offset:offset + 2], byteorder='little')
    offset += 2

    #!! tcCred --> SHOULD BE SOMETHING LIKE THIS:
    # !! trust as DER FORMAT || gateway cert as DER FORMTAT || key as BEARER FORMAT

    if tcCredLen > 0:
        # Read tcCred (tcCredLen bytes)
        tcCred = data[offset:offset + tcCredLen]
        offset += tcCredLen
    else:
        tcCred = ""

    # read sigLen (4 bytes, little endian)
    sigLen = int.from_bytes(data[offset:offset + 4], byteorder='little')
    offset += 4

    # Read keyCRC (4 bytes, little endian)
    keyCRC = int.from_bytes(data[offset:offset + 4], byteorder='little')
    offset += 4

    if sigLen > 0:
        # Read sig (sigLen bytes)
        sig = data[offset:offset + sigLen]
        offset += sigLen
    else:
        sig = ""

    # Read updLen (4 bytes, little endian)
    updLen = int.from_bytes(data[offset:offset + 4], byteorder='little')
    offset += 4

    if updLen > 0:
        # Read updData (updLen bytes)
        updData = data[offset:offset + updLen]
        offset += updLen
    else:
        updData = ""

    return {
        "cupsUriLen": cupsUriLen,
        "cupsUri": cupsUri,
        "tcUriLen": tcUriLen,
        "tcUri": tcUri,
        "cupsCredLen": cupsCredLen,
        "cupsCred": cupsCred,
        "tcCredLen": tcCredLen,
        "tcCred": tcCred,
        "sigLen": sigLen,
        "keyCRC": keyCRC,
        "sig": sig,
        "updLen": updLen,
        "updData": updData
    }


def build_payload(data):
    payload = bytearray()

    #cupsUriLen
    cupsUri = data.get("cupsUri", "")
    cupsUriLen = len(cupsUri)
    payload.append(cupsUriLen)

    # cupsUri (cupsUriLen bytes)
    if cupsUriLen > 0:
        payload.extend(cupsUri.encode())

    # tcUriLen
    tcUri = data.get("tcUri", "")
    tcUriLen = len(tcUri)
    payload.append(tcUriLen)

    # tcUri (tcUriLen bytes)
    if tcUriLen > 0:
        payload.extend(tcUri.encode())

    # cupsCredLen
    cupsCred = data.get("cupsCred", b"")
    cupsCredLen = len(cupsCred)
    payload.extend(cupsCredLen.to_bytes(2, byteorder='little'))

    #cupsCred (cupsCredLen bytes)
    if cupsCredLen > 0:
        payload.extend(cupsCred)

    #  tcCredLen
    tcCred = data.get("tcCred", b"")
    tcCredLen = len(tcCred)
    payload.extend(tcCredLen.to_bytes(2, byteorder='little'))

    # tcCred (tcCredLen bytes)
    if tcCredLen > 0:
        payload.extend(tcCred)

    # sigLen
    sig = data.get("sig", b"")
    sigLen = len(sig)
    payload.extend(sigLen.to_bytes(4, byteorder='little'))

    # keyCRC
    keyCRC = data.get("keyCRC", 0)
    payload.extend(keyCRC.to_bytes(4, byteorder='little'))

    # sig
    if sigLen > 0:
        payload.extend(sig)

    # updLen
    updData = data.get("updData", b"")
    updLen = len(updData)
    payload.extend(updLen.to_bytes(4, byteorder='little'))

    # updData (updLen bytes)
    if updLen > 0:
        payload.extend(updData)

    return bytes(payload)

data = {
    "cupsUri": "",
    "tcUri": "",
    "cupsCred": b"",
    "tcCred": b"",
    "sig": b"",
    "keyCRC": 123456789,
    "updData": b"update_data"
}

""" from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def pem_to_der(pem_cert):
    # Charger le certificat PEM
    cert = serialization.load_pem_x509_certificate(pem_cert.encode(), default_backend())
    
    # Convertir en DER
    der_cert = cert.public_bytes(encoding=serialization.Encoding.DER)
    
    return der_cert

payload = construct_payload(data)
print(payload) """


# this hex come from a real intercepted request from mitmproxy during cups api call
resp_hex= '00000000e6053082056b30820353a0030201020211008210cfb0d240e3594463e0bb63828b00300d06092a864886f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f74205831301e170d3135303630343131303433385a170d3335303630343131303433385a304f310b300906035504061302555331293027060355040a1320496e7465726e65742053656375726974792052657365617263682047726f7570311530130603550403130c4953524720526f6f7420583130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f41437f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c4493b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0be8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac870794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad641e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e5178150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d0275de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041479b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b05000382020100551f58a9bcb2a850d00cb1d81a6920272908ac61755c8a6ef882e5692fd5f6564bb9b8731059d321977ee74c71fbb2d260ad39a80bea17215685f1500e59ebcee059e9bac915ef869d8f8480f6e4e99190dc179b621b45f06695d27c6fc2ea3bef1fcfcbd6ae27f1a9b0c8aefd7d7e9afa2204ebffd97fea912b22b1170e8ff28a345b58d8fc01c954b9b826cc8a8833894c2d843c82dfee965705ba2cbbf7c4b7c74e3b82be31c822737392d1c280a43939103323824c3c9f86b255981dbe29868c229b9ee26b3b573a82704ddc09c789cb0a074d6ce85d8ec9efceabc7bbb52b4e45d64ad026cce572ca086aa595e315a1f7a4edc92c5fa5fbffac28022ebed77bbbe3717b9016d3075e46537c3707428cd3c4969cd599b52ae0951a8048ae4c3907cecc47a452952bbab8fbadd233537de51d4d6dd5a1b1c7426fe64027355ca328b7078de78d3390e7239ffb509c796c46d5b415b3966e7e9b0c963ab8522d3fd65be1fb08c284fe24a8a389daac6ae1182ab1a843615bd31fdc3b8d76f22de88d75df17336c3d53fb7bcb415fffdca2d06138e196b8ac5d8b37d775d533c09911ae9d41c1727584be0241425f67244894d19b27be073fb9b84f817451e17ab7ed9d23e2bee0d52804133c31039edd7a6c8fc60718c67fde478e3f289e0406cfa5543477bdec899be91743df5bdb5ffe8e1e57a2cd409d7e6222dade182700000000417574686f72697a6174696f6e3a204e4e5358532e534d494944354a4d4f44554644534d485046374a5a56334a56415853554b4259474c36534a37512e44554e4b3433453752334a4246464a524536364e514d4b43545535574b3458334c4336454d4a484c47534733485a5552504542510d0a000000000000000000000000'
hex_data = bytes.fromhex(resp_hex)
parsed_data = parse_response(hex_data)
for key, value in parsed_data.items():
    print(f"{key}: {value}")
