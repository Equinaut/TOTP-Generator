import hashlib

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