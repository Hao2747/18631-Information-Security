#The program use given cipher text first calculate Dec(C0) to Dec(C5). 
#Then Xor it with the encoded plaintext to get the first five blocks of ciphertext
#End the ciphertext with last C[5]



import subprocess
import time


def pad(s):
  return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def verify_input(cipher_blocks ):
    
    process = subprocess.Popen(["nc","192.168.2.83","10033"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
    input_terms = cipher_blocks + '\n'
    #print(input_terms)
    output = process.communicate(input=input_terms)[0] 
   
    #print(output)    
    if ("invalid padding" not in output):
        #print(output)
        return True
    else:
        return False

def find_last_byte(c_pre,c_cur):
    for guess in range(256):
        input = c_pre[:-2] + format(guess ^ 1 ^ int(c_pre[-2:],16), '02x') + c_cur
        # print(type(c_pre[:-2]))
        # print(type(format(guess ^ 1 ^ int(c_pre[-2:],16), '02x')))
        # start_time = time.time()       
        if (verify_input(input)):
            print("for Pn ends with {}, input cipher is {}. Feel free to verify manually".format(guess, input))
            if(guess == 1):
                continue
            else:
                correct_guess = guess
        else:
            continue
    print("Chose", correct_guess)
    return correct_guess ^ int(c_pre[-2:],16)
    

def cal_dec(c_pre, c_cur):

    dec_block = format(find_last_byte(c_pre, c_cur),'02x') # This is an int that is used to Xor Cn-1, so the Pn(Cn-1 xor Dec(Cn)) has its ending byte as 0
    #dec_block = format(block_end_clean ^ int(c_pre[-2:],16),'02x')
    # for loop to brute force every byte
    for block_index in range(1,16):
        print("dec_block", dec_block)
        leading_byte = c_pre[:(-2) * block_index ]
        ending_byte = format(block_index + 1, "02x") * block_index  
        ending_byte_cleaned = format(int(ending_byte, 16) ^ int(dec_block, 16), "0{}x".format(2*block_index))

        #Set the ending bytes of Cn-1 so it can XOR Dec(Cn) with correct ending
        #for loop to loop through all possible byte choice until it is valid padding
        
        
        for guess in range(0,256):
            
            input = leading_byte[:-2] + format(int(leading_byte[-2:], 16) ^ guess ^ (block_index + 1),'02x') + ending_byte_cleaned + c_cur
            
            
            if (verify_input(input)):
                # print(leading_byte)
                # print(ending_byte)
                # print(ending_byte_cleaned)
                # print("INPUT Pn ends with {}, input cipher is {}. Feel free to verify manually".format(guess, input))
                #print("guess",format(guess,'x'))
                dec_block = format(guess ^ int(leading_byte[-2:],16),'02x') + dec_block
                #block_end_clean += guess << block_index * 2
                break
            else:
                continue
    print("Final dec block", dec_block)
    return dec_block    

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
    plaintext = pad('{"username": "guest", "expires": "2030-01-07", "is_admin": "block_index <= 1"}').encode("hex")
    #break down the ciphertext to 6 blocks
    cipher = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]
    plain = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]
    
    #decrypt_attack(cipher)
    encrypt_attack(cipher,plain)
    
    #find_last_byte(cipher[3], cipher[4])
    # dec_block_string = ''
    #dec_block_string = cal_dec(cipher[2], cipher[3])
    

    # plain_hex = pad(plain).encode("hex")
    # #Calculate Dec(C1) - Dec(C5)
    # for i in range(len(cipher)-1, 0,-1):
   
    #     dec_block_string = cal_dec(cipher[i]) + dec_block_string

    # print("block string",dec_block_string)
    # correct_cookie = format(int(dec_block_string,16) ^ int(plain_hex,16), "0160x")
    # print("answer",correct_cookie)
   

    # #decrption attack
    # sample_cookie = format(int(dec_block_string,16) ^ int(cipher[:160],16), "0160x")
    # print("decryption", sample_cookie)
    