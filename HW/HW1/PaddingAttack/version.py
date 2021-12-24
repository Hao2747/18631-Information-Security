import subprocess
import time



ciphertext = '5468697320697320616e20495634353676f451dfe8f3a771cfdef0a3675c3f608b00ef8672e052721691b2cfb637e58faca4b94cfe0a3abd168f71f3adbbcf5bca90e1bfff9a413789b032e1c4186f1343dcddb0e04c0ddf86412c93ad7f93c5'
#ciphertext = bytearray(ciphertext)

cipher = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]

print(cipher)



dec_byte = 0
block_end_clean = 0
dec_block = ''
for pos_in_block in range(16):
    print("shift {} block".format(pos_in_block))
    
    candidate =[]
    time_used = []
    # for i in range(pos_in_block):
    #         block_end_clean += dec_byte << i   
     #Set the ending bytes of Cn-1 so it can XOR Dec(Cn) with correct ending
    for guess in range(1,256):
        if (pos_in_block == 0):
            start_time = time.time()
        #Manipulate the last bit to send for attack
        
        
        new_input_int = (guess ^ (pos_in_block + 1)) << (pos_in_block * 8) #
        new_input_int += block_end_clean
        new_input = format( new_input_int,'032x') #Convert 
        #print("new input:",new_input)
        input_term = new_input + cipher[5]
        process = subprocess.Popen(["nc","127.0.0.1","23555"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        input_terms = input_term + '\n'
        #print("input term", input_terms)
        output = process.communicate(input=input_terms)[0]      
        #print(output)
        
        #print("Time passed:", elapsed)
        if ("invalid padding" not in output):
            if (pos_in_block == 0):
                end_time = time.time()
                elapsed = end_time - start_time
                candidate.append(guess)
                time_used.append(end_time)
                
                print("valid",guess)
            else:
                dec_byte = guess
                dec_block =   format(dec_byte, "02x") + dec_block
                print("dec block", dec_block)
                block_end_clean = int(dec_block, 16)
                
                for i in range(pos_in_block + 1):
                    block_end_clean ^= ((pos_in_block + 2) << (i * 8))
                break
            #print("Time passed:", elapsed)
            #print("Valid padding:" + input_term)
            # print(hex(guess))
            #print("new input:",new_input)
            
    if (pos_in_block == 0):
        dec_byte = candidate[time_used.index(max(time_used))] 
        print("# from a list", len(candidate))
        dec_block =   format(dec_byte, "02x") + dec_block
        
        print("dec block", dec_block)
        block_end_clean = int(dec_block, 16)
        
        for i in range(pos_in_block + 1):
            block_end_clean ^= ((pos_in_block + 2) << (i * 8))
        #print("here,",hex(block_end_clean))
    #last_sec_block_int = cipher[4][:(-2)*(pos_in_block * 2)] + 
    
    


   
    