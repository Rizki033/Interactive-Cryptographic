# The string to be encrypted/decrypted
message = 'This is my secret message.'
#the encryption/ decryption key
key = 17
#Wheter the program encrypts or decrypts 
mode = 'encrypt' # set to 'decrypt' to decrypt 
#Every possible symbol that can be encrypted/decrypted
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
#Store the encrypted/decrypted from  of the message:
translated = ''
for symbol in message:
  # only symbols in the SYMBOLS string can be encrypted/decrypted
  if symbol in SYMBOLS:
    symbolIndex = SYMBOLS.find(symbol)
    # perform encryption/decryption :
    if mode == 'encrypt':
      translatedIndex = symbolIndex + key 
    elif mode == 'decrypt':
      translatedIndex = symbolIndex - key 
    # handle wrap-around if needed
    if translatedIndex >= len(SYMBOLS):
      translatedIndex = translatedIndex - len(SYMBOLS)
    elif translatedIndex < 0:
      translatedIndex = translatedIndex + len(SYMBOLS)
      
    translated = translated + SYMBOLS[translatedIndex]
  else:
    translated = translated + symbol    
print(translated)
