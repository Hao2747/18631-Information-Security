#The program should be run in Python 2
#The program use given ciphertext first calculate Dec(C0) to Dec(C5). 
#For encryption attack: Use Dec(C0) to Dec(C5) to Xor the encoded plaintext in a strict manner to get the first five blocks of ciphertext
#For decryption attack: Use Dec(C0) to Dec(C5) to IV to C(4) to get Xor P(0) to P(5)
#Note: int(string, 16) converts a string of hex to its decimal equivalent. It has been done many times in the program for XOR operation 
#      format(number,"08x") converts a interger to its hex form in string. It will pad leading 0 until it reaches 8 char  

import subprocess



def pad(s):
  return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

#This function pass in a cipertext (or plaintext), nc to the server and verify if the padding is valid
def verify_input(cipher_blocks):   
    process = subprocess.Popen(["nc","127.0.0.1","23555"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
    input_terms = cipher_blocks + '\n'
    output = process.communicate(input=input_terms)[0] 
    if ("invalid padding" not in output):
        return True
    else:
        return False

#This function check if the final byte has the correct ending
def find_last_byte(c_pre,c_cur):
    for guess in range(256):
        #Brute force guess that is equal to guess ^ 1 ^ original cipertext. This is becausee the guess will be equal to plaintext
        input = c_pre[:-2] + format(guess ^ 1 ^ int(c_pre[-2:],16), '02x') + c_cur
   
        if (verify_input(input)):
            if(guess == 1): 
                continue
            else:
                correct_guess = guess
        else:
            continue
    #correct guess = plaintext, last two character of C_pre is the original text in target position. Their Xor is the Dec(Cn)
    return correct_guess ^ int(c_pre[-2:],16)    
    
#This function takes in the Cn-1 and Cn. It calculates Dec(cn)
def cal_dec(c_pre, c_cur):
    # This is the Dec(Cn) hex string 
    dec_block = format(find_last_byte(c_pre, c_cur),'02x') 
    #dec_block = format(block_end_clean ^ int(c_pre[-2:],16),'02x')
    # for loop to brute force every block Cn-1
    for block_index in range(1,16):
        # Take the leading byte from original Cn-1. After every iteration, set the ending byte of Cn-1 so that Pn can be valid padding
        leading_byte = c_pre[:(-2) * block_index ]
        ending_byte = format(block_index + 1, "02x") * block_index  
        ending_byte_cleaned = format(int(ending_byte, 16) ^ int(dec_block, 16), "0{}x".format(2*block_index))

        #for loop to loop through all possible byte choice until it is valid padding       
        for guess in range(0,256):
            #Format the input by concatenating leading bytes, our target brute force byte, ending byte and Cn         
            input = leading_byte[:-2] + format(int(leading_byte[-2:], 16) ^ guess ^ (block_index + 1),'02x') + ending_byte_cleaned + c_cur
            #Once find the correct input, jump out of the loop to find next one.
            if (verify_input(input)):
                dec_block = format(guess ^ int(leading_byte[-2:],16),'02x') + dec_block
                break
            else:
                continue
    return dec_block    

#For every Cn and Cn-1, find its Dec(Cn). All Dec(Cn) Xor C(0) to C(5) gives correct plaintext
def decrypt_attack(cipher):
    dec_string = ''
    for i in range(5,0,-1):
        dec_string = cal_dec(cipher[i-1],cipher[i]) + dec_string
    cipher.pop()
    cipher_in_hex = "".join(cipher)
    plain = format(int(cipher_in_hex, 16) ^ int(dec_string,16),'x')
    plaintext = plain.decode("hex")
    print(plaintext)
    return plaintext           

#Take Cn-1 and Cn, find Dec(Cn). Then use the desired plaintext P(n) Xor Dec(Cn) to find correct Cn-1. 
#Use this Cn-1 with Cn-2 to iterate again           
def encrypt_attack(cipher, plain):
    for i in range(5,0,-1):
        print("start solving dec block of ", i)
        dec_cur = cal_dec(cipher[i-1],cipher[i])
        cipher[i-1] = format(int(dec_cur, 16) ^ int(plain[i-1],16),'032x')
        print("new cipher",cipher[i-1])
    print(cipher)
    print("".join(cipher))
    return cipher
        
if __name__ == "__main__":
    ciphertext = '5468697320697320616e20495634353676f451dfe8f3a771cfdef0a3675c3f608b00ef8672e052721691b2cfb637e58faca4b94cfe0a3abd168f71f3adbbcf5bca90e1bfff9a413789b032e1c4186f1343dcddb0e04c0ddf86412c93ad7f93c5'
    plaintext = pad('{"username": "guest", "expires": "2030-01-07", "is_admin": "true"}').encode("hex")
    #break down the ciphertext to 6 blocks
    cipher = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]
    plain = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]
    
    decrypt_attack(cipher)
    encrypt_attack(cipher,plain)
   