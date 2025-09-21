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
