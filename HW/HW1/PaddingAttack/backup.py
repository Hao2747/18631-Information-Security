import subprocess
import time


# Code referred from https://nitratine.net/blog/post/xor-python-byte-strings/
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


ciphertext = '5468697320697320616e20495634353676f451dfe8f3a771cfdef0a3675c3f608b00ef8672e052721691b2cfb637e58faca4b94cfe0a3abd168f71f3adbbcf5bca90e1bfff9a413789b032e1c4186f1343dcddb0e04c0ddf86412c93ad7f93c5'
#ciphertext = bytearray(ciphertext)

cipher = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]

print(cipher)

correct_block = []
last_sec_block_int = int(cipher[4],16)
#block_end_clean = last_sec_block_int #a block with its end goal for ending all 0
print("0.:\\n",last_sec_block_int)
dec_byte = 0
block_end_clean = 0
dec_block = ''
for pos_in_block in range(16):
    print("shift {} block".format(pos_in_block))
    
    candidate =[]
    time_used = []
    # for i in range(pos_in_block):
    #         block_end_clean += dec_byte << i   
    for guess in range(1,256):
        start_time = time.time()
        #Manipulate the last bit to send for attack
        
        
        new_input_int = (guess ^ (pos_in_block + 1)) << (pos_in_block * 8) #
        new_input_int += block_end_clean     #Set the ending bytes of Cn-1 so it can XOR Dec(Cn) with correct ending
        new_input = format( new_input_int,'032x') #Convert 
        #print("new input:",new_input)
        
        # print(last_sec_int)
        # print(cipher)
        
        input_term = new_input + cipher[5]
        process = subprocess.Popen(["nc","127.0.0.1","23555"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        input_terms = input_term + '\n'
        #print("input term", input_terms)
        output,error = process.communicate(input=input_terms)
        
        end_time = time.time()
        elapsed = end_time - start_time
        #print("Time passed:", elapsed)
        if ("invalid padding" not in output):
            candidate.append(guess)
            time_used.append(end_time)
            #print("Time passed:", elapsed)
            print("Valid padding:" + input_term)
            print(hex(guess))
            #print("new input:",new_input)
            
    dec_byte = candidate[time_used.index(max(time_used))] 
    dec_block =   format(dec_byte, "02x") + dec_block
    print("dec block", dec_block)
    block_end_clean = int(dec_block, 16)
    
    for i in range(pos_in_block + 1):
        block_end_clean ^= ((pos_in_block + 2) << (i * 8))
        #print("here,",hex(block_end_clean))
    
    


   
    