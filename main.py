#Caesar cipher

message = 'Hello Zaira'
offset = 3

def caesar(message, offset):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    encrypted_message = ''

    for char in message.lower():
        if char == ' ':
            encrypted_message += char
        else:
            index = alphabet.find(char)
            new_index = (index + offset) % len(alphabet)
            encrypted_message += alphabet[new_index]
    print('plain message:', message)
    print('encrypted message:', encrypted_message)

# (index + offset) % len(alphabet) is used to avoid index error for cases when, for example, "z" char + 3 is out of range of alphabet's possible index no.
# message.lower() is used to prevent mistakes when Upper-case chars are used
# encrypted_message += char = encrypted_message = encrypted_message + char
# .find(char) - is used to find the alphabetical index no. of the message character(char)
# alphabet can be expanded with other symbols
# caesar(message, offset) or caesar(message, 3) are to similar ways to call function
caesar(message, 3)


#Vigenere cipher
text = 'mrttaqrhknsw ih puggrur'    #text to be ciphred
custom_key = 'happycoding'          #password

def vigenere(message, key, direction=1):     
    #by assigning direction=1, encryption works in normar way, if direction=-1 it is mean decryption as code works in oposite direction
    key_index = 0     
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    final_message = ''

    for char in message.lower():

        # .isalpha() is a boolean used to append any non-letter character to the message
        if not char.isalpha():      
            final_message += char
        else:        
            # Find the right key character to encode/decode
            key_char = key[key_index % len(key)]       #added to avoid cases when custom_key is longer than text
            key_index += 1

            # Define the offset and the encrypted/decrypted letter
            offset = alphabet.index(key_char)
            index = alphabet.find(char)
            new_index = (index + offset*direction) % len(alphabet)
            final_message += alphabet[new_index]
    
    return final_message

def encrypt(message, key):
    return vigenere(message, key)         #third argument is absent as it is used "direction=1" by default from vigenere function
    
def decrypt(message, key):
    return vigenere(message, key, -1)

print(f'\nEncrypted text: {text}')        
print(f'Key: {custom_key}')               #string formatter equals to print('Key: ' + custom_key)
decryption = decrypt(text, custom_key)
print(f'\nDecrypted text: {decryption}\n')
