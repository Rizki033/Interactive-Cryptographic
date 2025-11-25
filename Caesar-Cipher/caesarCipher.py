# The string to be encrypted/decrypted
message = 'This is my secret message.'
#the encryption/ decryption key
key = 17
#Wheter the program encrypts or decrypts 
made = 'encrypt' # set to 'decrypt' to decrypt 
#Every possible symbol that can be encrypted/decrypted
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
#Store the encrypted/decrypted from  of the message:
translated = ''
for symbol in message:
  # only symbols in the SYMBOLS string can be encrypted/decrypted
  