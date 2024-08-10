import hashlib
import time
import urllib.parse

# Text file where keys are stored in key URI format
KEY_FILE = "keys.txt"

# Block size and output size for SHA1
BLOCK_SIZE =  64
OUTPUT_SIZE = 20

def HMAC_SHA1(key, message):
    # Computes the HMAC-SHA1 value of a given key and message
    k0 = bytearray(BLOCK_SIZE)
    k0[:len(key)] = key

    k0_ipad = bytearray(k0)
    k0_opad = bytearray(k0)

    # Calculate k0_ipad and k0_opad by XORing X0 with ipad and opad
    for i in range(0, BLOCK_SIZE): 
        k0_ipad[i] ^= 0x36    
        k0_opad[i] ^= 0x5c

    # Append the message to k0_ipad
    k0_ipad_message = bytearray(BLOCK_SIZE + len(message))
    k0_ipad_message[:BLOCK_SIZE] = k0_ipad
    k0_ipad_message[BLOCK_SIZE:] = message
    
    # Calculate the digest of k0_ipad_message
    hash1 = hashlib.sha1(k0_ipad_message).digest()

    # Append hash1 to k0_opad
    k0_opad_hash1 = bytearray(BLOCK_SIZE + OUTPUT_SIZE)
    k0_opad_hash1[:BLOCK_SIZE] = k0_opad
    k0_opad_hash1[BLOCK_SIZE:] = hash1

    # Calculate the digest of k0_opad_hash1 to produce the final HMAC value
    hmac = hashlib.sha1(k0_opad_hash1).digest()
    return hmac

def generate_code(key, time, digits = 6, period = 30):
    # Generate a TOTP code for a given key and time stamp
    # Defaults to 6 digit codes that last 30 seconds

    # Create 8 byte counter value
    counter = bytearray([((time // period) >> 8 * i) & 0xff for i in range(7, -1, -1)])

    # Calculate HMAC value
    hmac = HMAC_SHA1(key, counter)

    # Calculate TOTP code from the HMAC value
    offsetBits = hmac[19] & 0xf
    vals = "".join(bin(i)[2:].zfill(8) for i in hmac[offsetBits : offsetBits + 4])
    return str(int(vals[1:], base = 2) % 10 ** digits).zfill(digits)

def convert_secret(secret):
    # Converts a base 32 encoded secret into a byte array
    values = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    # Convert base 32 digits to binary
    binaryValues = [bin(values.index(c))[2:].zfill(5) for c in secret]
    joined = "".join(binaryValues)
    
    # Split binary digits into bytes
    bytes = [int(joined[i: i + 8], base = 2) for i in range(0, len(joined), 8)]
    
    return bytearray(bytes)

if __name__ == "__main__":
    # Read secrets from text file
    with open(KEY_FILE) as file:
        for line in file.readlines():
            # Parse key URI
            parsed_uri = urllib.parse.urlparse(line)
            params = urllib.parse.parse_qs(parsed_uri.query)
            if "secret" not in params: continue
            secret = params["secret"][0]
            digits = int(params["digits"][0]) if "digits" in params else 6
            period = int(params["period"][0]) if "period" in params else 30

            # Generate the TOTP code with the relevant parameters
            generated_code = generate_code(
                key = convert_secret(secret),
                time = int(time.time()),
                digits = digits,
                period = period
            )
            print(f"{urllib.parse.unquote(parsed_uri.path)[1:]} - {generated_code}")