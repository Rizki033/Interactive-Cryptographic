# Caesar Cipher Hacker
message = 'guv6Jv6Jz!J6rp5r7Jzr66ntrM'
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

# loop through every possible key:
for key in range(len(SYMBOLS)):
  # it is important to set translated to the blank string so that the 
  # previous interation's value for translated is cleared.
  translated = ''
  
  # the rest of the program is almost the same as the Caesar cipher program:
  # Loop through each symbol in the message :
  for symbol in message:
    if symbol in SYMBOLS:
      symbolIndex = SYMBOLS.find(symbol)
      translatedIndex = symbolIndex - key 
      
      # handle the wraparound :
      if translatedIndex < 0:
        translatedIndex = translatedIndex + len(SYMBOLS)
        
      # Appnend the decrypted symbol :
      translated = translated + SYMBOLS[translatedIndex]
    
    else:
      # Append the symbol without encrypting/decrypting :
      translated = translated + symbol
      
  # Display the key being tested, along with its decrypted message:
  print('key #%s: %s' % (key, translated))
      