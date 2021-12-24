#The program use given cipher text first calculate Dec(C0) to Dec(C5). 
#Then Xor it with the encoded plaintext to get the first five blocks of ciphertext
#End the ciphertext with last C[5]



import subprocess
import time

def pad(s):
  return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def cal_dec(cipher_block):

    dec_byte = 0
    block_end_clean = 0
    dec_block = ''
    # for loop to brute force every byte
    for pos_in_block in range(16):
        candidate =[]
        time_used = []
      
        #Set the ending bytes of Cn-1 so it can XOR Dec(Cn) with correct ending
        #for loop to loop through all possible byte choice until it is valid padding
        for guess in range(0,256):
            if (pos_in_block <= 1):
                start_time = time.time()
            #Manipulate the last bit to send for attack           
            new_input_int = (guess ^ (pos_in_block + 1)) << (pos_in_block * 8) #change the brute force byte
            new_input_int += block_end_clean   #Set the ending byte with correct ending. e.g.(XXXX/0x02/0x02)
            new_input = format( new_input_int,'032x') #Convert it into proper entry
            input_term = new_input + cipher_block
            process = subprocess.Popen(["nc","192.168.2.83","10033"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
            input_terms = input_term + '\n'
            output = process.communicate(input=input_terms)[0]      
            if ("invalid padding" not in output):
                #To counter corner cases, use timing attack. Take the padding that costs longest to solve.
                #To cut down total time, only do it to the last couple of byte
                if (pos_in_block <= 10):
                    end_time = time.time()
                    elapsed = end_time - start_time
                    candidate.append(guess)
                    time_used.append(elapsed)                   
                #Some repeat code here to break the loop for faster run time
                else:
                    #we guessed out a guess in Cn-1[m] that can make the padding correct. This guess is the Dec(Cn)[m] byte 
                    dec_byte = guess
                    dec_block = format(dec_byte, "02x") + dec_block
                    block_end_clean = int(dec_block, 16)
                    
                    for i in range(pos_in_block + 1):
                        block_end_clean ^= ((pos_in_block + 2) << (i * 8))
                    break
            #Based on the timing, pick the longest guess
        if (pos_in_block <= 10):
            dec_byte = candidate[time_used.index(max(time_used))] 
            dec_block = format(dec_byte, "02x") + dec_block
            
            print("dec block", dec_block)
            block_end_clean = int(dec_block, 16)
            
            for i in range(pos_in_block + 1):
                block_end_clean ^= ((pos_in_block + 2) << (i * 8))
    return dec_block


def encrypt_attack(cipher, plain):
    for i in range(5,0,-1):
        print("start solving dec block of ", i)
        dec_cur = cal_dec(cipher[i])
        cipher[i-1] = format(int(dec_cur, 16) ^ int(plain[i-1],16),'032x')
        print("new cipher",cipher[i-1])
    print(cipher)
    print("".join(cipher))
    return cipher   
if __name__ == "__main__":
    #ciphertext = '5468697320697320616e20495634353676f451dfe8f3a771cfdef0a3675c3f608b00ef8672e052721691b2cfb637e58faca4b94cfe0a3abd168f71f3adbbcf5bca90e1bfff9a413789b032e1c4186f1343dcddb0e04c0ddf86412c93ad7f93c5'
    #break down the ciphertext to 6 blocks
    ciphertext = '5468697320697320616e204956343536992bb019d910295f5b527e6e8cdecc2e26c7cc2a6668aa504c9e4321a540e14a1f8f318829d7667fa2c145f0a72ffd3ee172b48f6db8b101dc8313b006fdd8fac68a748c153acba603bcb0b54fd5345b'
    plaintext = pad('{"username": "guest", "expires": "2030-01-07", "is_admin": "block_index <= 1"}').encode("hex")
    #break down the ciphertext to 6 blocks
    cipher = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]
    plain = [plaintext[i:i+32] for i in range(0, len(plaintext), 32)]
    
    
    encrypt_attack(cipher,plain)