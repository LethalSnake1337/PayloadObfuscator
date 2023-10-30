import sys
import binascii
from arc4 import ARC4
import ipaddress
import macaddress
import uuid

def generate_code(data, length):
    print(f""" unsigned char payload[{length}] = {{
    {data}
    }};""")


def rc4(key, data):
    cipher = ARC4(key)
    encrypted = cipher.encrypt(data)

    # Beautifier for Code Generation
    formatted_data = ", ".join([f"0x{byte:02X}" for byte in encrypted])
    formatted_data = [formatted_data[i:i + 60] for i in range(0, len(formatted_data), 60)]
    formatted_string = '\n    '.join(formatted_data)

    # Generate Code
    generate_code(formatted_string, (len(encrypted)))
    return encrypted

def ipv4(data):
    # Padding data must be multiple of 4
    while (len(data) // 2) % 4 != 0:
        data += b'\x00'
    # Divide through 4 because we will use later 4 bytes in one loop run to generate an ipv4 address
    print(f"unsigned char* rawData[{len(data) // 4}] = " + "{")
    i = 0
    count = 0
    j = 4
    while i <= len(data) - 4:
        # Print last IPv4 address
        if i == len(data) - 4:
            print(f"\"{ipaddress.IPv4Address(data[i:j])}\"" + "\n};")
            break
        # Line break after 5 IPv4 addresses
        if count == 5:
            print(f"\"{ipaddress.IPv4Address(data[i:j])}\",")
            count = 0
        else:
            print(f"\"{ipaddress.IPv4Address(data[i:j])}\",", end="")
        i += 4
        j += 4
        count += 1
    return data


def ipv6(data):
    # Padding data must be multiple of 16
    while (len(data) // 2) % 16 != 0:
        data += b'\x00'
    print(data)
    print(len(data))
    # Divide through 16 because we will use later 4 bytes in one loop run to generate an ipv6 address
    print(f"unsigned char* rawData[{len(data) // 16}] = " + "{")
    i = 0
    count = 0
    j = 16
    while i <= len(data) - 16:
        count += 1
        if i == len(data) - 16:
            print(f"\"{ipaddress.IPv6Address(data[i:j])}\"" + "\n};")
            break
        if count == 3:
            print(f"\"{ipaddress.IPv6Address(data[i:j])}\", ")
            count = 0
        else:
            print(f"\"{ipaddress.IPv6Address(data[i:j])}\", ", end="")

        i += 16
        j += 16
    return data


def uuid1(data):
    # Padding data must be multiple of 16
    while (len(data) // 2) % 16 != 0:
        data += b'\x00'
    print(data[1:6])
    print(len(data))
    # Divide through 16 because we will use later 4 bytes in one loop run to generate an ipv6 address
    print(f"unsigned char* rawData[{len(data) // 16}] = " + "{")
    i = 0
    count = 0
    j = 16
    while i <= len(data) - 16:
        count += 1
        if i == len(data) - 16:
            #print(f"\"{uuid.UUID(data[i:j])}\"" + "\n};")
            print(f"\"{uuid.UUID(bytes_le=data[i:j])}\"" + "\n};")
            break
        if count == 3:
            #print(f"\"{uuid.UUID(data[i:j])}\", ")
            print(f"\"{uuid.UUID(bytes_le=data[i:j])}\", ")
            count = 0
        else:
            #print(f"\"{uuid.UUID(data[i:j])}\", ", end="")
            print(f"\"{uuid.UUID(bytes_le=data[i:j])}\", ", end="")

        i += 16
        j += 16
    return data


def mac(data):
    # Padding data must be multiple of 16
    while (len(data) // 2) % 6 != 0:
        data += b'\x00'
    print(data)
    print(len(data))
    # Divide through 16 because we will use later 4 bytes in one loop run to generate an ipv6 address
    print(f"unsigned char* rawData[{len(data) // 6}] = " + "{")
    i = 0
    count = 0
    j = 6
    while i <= len(data) - 6:
        count += 1
        if i == len(data) - 6:
            print(f"\"{macaddress.MAC(data[i:j])}\"" + "\n};")
            break
        if count == 3:
            print(f"\"{macaddress.MAC(data[i:j])}\", ")
            count = 0
        else:
            print(f"\"{macaddress.MAC(data[i:j])}\", ", end="")

        i += 6
        j += 6
    return data


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("[!] Usage: obfuscator.py <Payload file> <Option>\n")
        print("""
        Options:\n
            - rc4 (Encryption)
            - ipv4 (Obfuscation)
            - ipv6 (Obfuscation)
            - uuid (Obfuscation)
            - mac (Obfuscation)
        """)
    else:
        # Open File
        file = open(sys.argv[1], 'rb')
        payload = file.read()

        # check option
        if sys.argv[2] == "rc4":
            key = input("[!] Enter the Encryption Key: ")
            key1 = bytes(key, 'utf-8') + b'\x00'
            print(f"[+] Encrypting...")
            print(binascii.hexlify(rc4(key1, payload)))
        elif sys.argv[2] == "ipv4":
            print(binascii.hexlify(ipv4(payload)))
        elif sys.argv[2] == "ipv6":
            print(binascii.hexlify(ipv6(payload)))
        elif sys.argv[2] == "uuid":
            print(binascii.hexlify(uuid1(payload)))
        elif sys.argv[2] == "mac":
            print(binascii.hexlify(mac(payload)))
