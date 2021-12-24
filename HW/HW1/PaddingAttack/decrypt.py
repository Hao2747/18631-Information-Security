
# for ():
#     what last_sec_block_int is
#     for(every byte of every block):
#         for (different guesses):
#             try all possible guesses
#         figure out the correct byte guess -> append to correct block
#         block_end_clean ^= correct_byte
#         last_sec_block_int = block_end_clean
#     figure out the correct blcok guess -> append to correct string






import subprocess
import time


# Code referred from https://nitratine.net/blog/post/xor-python-byte-strings/
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


ciphertext = '5468697320697320616e20495634353676f451dfe8f3a771cfdef0a3675c3f608b00ef8672e052721691b2cfb637e58faca4b94cfe0a3abd168f71f3adbbcf5bca90e1bfff9a413789b032e1c4186f1343dcddb0e04c0ddf86412c93ad7f93c5'
#ciphertext = bytearray(ciphertext)

cipher = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]

print(cipher)
candidate =[]
time_used = []
correct_block = []
last_sec_block_int = int(cipher[4],16)
block_end_clean = last_sec_block_int #a block with its end goal for ending all 0
print("0.:\\n",last_sec_block_int)
for pos_in_block in range(16):
    print("shift {} block".format(pos_in_block))
    
    for guess in range(1,127):
        start_time = time.time()
        #Manipulate the last bit to send for attack
        
        
        new_input_int = last_sec_block_int ^ ((guess ^(pos_in_block + 1)) << pos_in_block * 8) 
        new_input = format( new_input_int,'32x') #Convert 
        #print("new input:",new_input)
        
        # print(last_sec_int)
        # print(cipher)
        
        input_term = cipher[0] + cipher[1] + cipher[2] + cipher[3] + new_input + cipher[5]
        process = subprocess.Popen(["nc","127.0.0.1","23555"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        input_terms = input_term + '\n'
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
            print("new input:",new_input)
            
    correct_byte = candidate[time_used.index(max(time_used))]
    correct_block.append(correct_byte)
    block_end_clean ^= (correct_byte << pos_in_block * 8)
    print("clean block", hex(block_end_clean))
    last_sec_block_int = block_end_clean  #Modify the last byte (c_0') in ciphertext for next attack
    
    #PRoblem HER#E
    
    # for i in range(pos_in_block+2):

    #     last_sec_block_int ^= (pos_in_block+2) << (i*8)
    #     print("i",i)
    #     print("pos_in", pos_in_block)
    #     print("last", hex(last_sec_block_int))
    # #last pos_in_block byte
    # # print("correct guess:",correct_byte)
    # # print("blcok int before chage:",last_sec_block_int)
    # # print("1.",correct_byte << (pos_in_block * 8))
    # # print("2.",pos_in_block + 2)
    # # print("3.",last_sec_block_int ^ ((correct_byte^ (pos_in_block + 2)) << (pos_in_block * 8)) )
    
    # # if ("L" in str(last_sec_block_int) or "l" in str(last_sec_block_int)):
    # #     str(last_sec_block_int
    # print("last sec_bol:", hex(last_sec_block_int))
#cipher[4] = cipher[4] & ((~./ff0b11111100 << 0) | (correct_byte << 0)
       
   
   
   
   
   
   
   
   
   
   