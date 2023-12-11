import binascii
import struct

def KSA(key):
    # IV || KEY
    S = list(range(256)) # init S to be identity permutation
    # a = bytes(0xb9026f)
    # S = list(a)

    j = 0
    for i in range(256): # 0 to 255
        # keylength = number of bytes in key; ASCII --> 1 char = 1 byte
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    return S

def PRGA(S):
    i, j = 0, 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        third_element = (S[i] + S[j]) % 256
        K = S[third_element]
        yield K
        
def RC4(key):
    S = KSA(key)
    return PRGA(S)

def decrypt(key, ciphertext):
    """
    key: hexadecimal
    ciphertext: hexadecimal
    """
    # generate key stream
    key_hex = binascii.unhexlify(key)
    keystream = RC4(key_hex)

    plaintext = ""
    for i in binascii.unhexlify(ciphertext):
        plaintext += ('{:02X}'.format(i ^ next(keystream)))

    return plaintext

def encrypt(key, plaintext):
    """
    key: hexadecimal
    ciphertext: hexadecimal
    """
    # generate key stream
    key_hex = binascii.unhexlify(key)
    keystream = RC4(key_hex)

    ciphertext = ""
    for i in binascii.unhexlify(plaintext):
        ciphertext += ('{:02X}'.format(i ^ next(keystream)))
    
    return ciphertext

if __name__ == '__main__':
    # RC4 algorithm please refer to http://en.wikipedia.org/wiki/RC4

    ## key = a list of integer, each integer 8 bits (0 ~ 255)
    ## ciphertext = a list of integer, each integer 8 bits (0 ~ 255)
    ## binascii.unhexlify() is a useful function to convert from Hex string to integer list

    """
    RC4 TESTING
    """
    ## Cracking the ciphertext
    #     Several test cases: (to test RC4 implementation only)
    #     1. key = '1A2B3C', cipertext = '00112233' -> plaintext = '0F6D13BC'
    #     2. key = '000000', cipertext = '00112233' -> plaintext = 'DE09AB72'
    #     3. key = '012345', cipertext = '00112233' -> plaintext = '6F914F8F'
    print("=================================\nRC4 TEST CASES\n=================================")
    test_ciphertext = '00112233'
    print(f"TEST CASE 1: {'0F6D13BC' == decrypt(key = '1A2B3C', ciphertext=test_ciphertext)}")
    print(f"TEST CASE 2: {'DE09AB72' == decrypt(key = '000000', ciphertext=test_ciphertext)}")
    print(f"TEST CASE 3: {'6F914F8F' == decrypt(key = '012345', ciphertext=test_ciphertext)}")
    print("=================================")

    ## Check ICV
    IV = "cdd23a"
    ICV = "5db2d69a"
    key ='1F1F1F1F1F'
    ciphertext2 = "c5e4b0c3ea87a1cd9b4b23f7076011ea0f8d89fb144430ab1b0bf44c2b32822881251e3d0829915d5837c2d2f7edec86b6d855e1668b" + ICV
    print(f"IV: 0x{IV}",)
    print(f"ICV: 0x{ICV}")

    decrypted_payload = decrypt(key=(IV + key), ciphertext=ciphertext2)
    print("decrypted payload with crc:", decrypted_payload)

    ICV_bytes_length = len(ICV) # ICV is concatenated with message
    crc_from_payload = decrypted_payload[-ICV_bytes_length:] # splice payload to find ICV
    print("crc from decrypted payload:", crc_from_payload)

    payload = decrypted_payload[:-ICV_bytes_length]
    print("data without crc:", payload)
    crcle = binascii.crc32(bytes.fromhex(payload)) & 0xffffffff # calculate icv / crc using CRC32
    calculated_crc = struct.pack('<L', crcle).hex().upper() # convert crc to big endian
    print("calculated crc using binascii.crc32: ",calculated_crc)

    encrypted_payload = encrypt(key=(IV+key), plaintext=(payload+calculated_crc))
    print(f"newly encrypted payload: {encrypted_payload}")
    print(f"newly encrypted payload ICV == 0x{ICV}: {encrypted_payload[-ICV_bytes_length:].lower() == ICV}")