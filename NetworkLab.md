# KB04 

![image](https://user-images.githubusercontent.com/92283038/185402940-ff37803e-2287-43e4-bae0-8a84464d0ff1.png)

Follow TCP Stream thì ta phát hiện một đoạn code python dùng để encode flag

```py
import string
import random
from base64 import b64encode, b64decode

FLAG = 'flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'

enc_ciphers = ['rot13', 'b64e', 'caesar']
# dec_ciphers = ['rot13', 'b64d', 'caesard']

def rot13(s):
	_rot13 = string.maketrans( 
    	"ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
    	"NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
	return string.translate(s, _rot13)

def b64e(s):
	return b64encode(s)

def caesar(plaintext, shift=3):
    alphabet = string.ascii_lowercase
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    table = string.maketrans(alphabet, shifted_alphabet)
    return plaintext.translate(table)

def encode(pt, cnt=50):
	tmp = '2{}'.format(b64encode(pt))
	for cnt in xrange(cnt):
		c = random.choice(enc_ciphers)
		i = enc_ciphers.index(c) + 1
		_tmp = globals()[c](tmp)
		tmp = '{}{}'.format(i, _tmp)

	return tmp

if __name__ == '__main__':
	print encode(FLAG, cnt=?)
```

Vậy bây giờ nhiệm vụ của chúng ta là đảo ngược lại quá trình encode để lấy flag. 
Đầu tiên ta sẽ phân tích hàm **encode**

```py
def encode(pt, cnt=50):
	tmp = '2{}'.format(b64encode(pt))
	for cnt in xrange(cnt):
		c = random.choice(enc_ciphers)
		i = enc_ciphers.index(c) + 1
		_tmp = globals()[c](tmp)
		tmp = '{}{}'.format(i, _tmp)
```

Đầu tiên nó sẽ dùng base64 để encode và thêm số 2 vào đầu. 

tiếp theo là trong vòng lặp với **cnt** lần : 

c sẽ được chọn random 1 trong 3 cách để encode 
```py
    enc_ciphers = ['rot13', 'b64e', 'caesar']
```
i sẽ là tổng index của enc_ciphers + 1

Sau đó chương trình sẽ encode flag và thêm giá trị i vào đầu ==> i sẽ cho chúng ta biết chương trình đã encode bằng cách nào, có 3 trường hợp :

```
i - 1 = 0 : rot13
i - 1 = 1 : b64e
i - 1 = 2 : caesar
```

Ok, giờ ta chỉ việc bruteforce số lần lặp **cnt** là có thể decode đoạn flag mã hóa. Vì chương trình được viết bằng python2 nên mình gặp chút khó khăn vì systax error 
khi cố decode bằng python trực tiếp trên code của đề, cảm ơn anh bạn Jinn#8802 đã giúp mình viết lại bằng python3.

Script Solve : 
```
import base64
import string
import random
from base64 import b64decode,b64encode
alphabet = string.ascii_lowercase
enc_ciphers = ['rot13', 'b64d', 'caesar_decrypt']
def rot13(s):
    res = ""
    charset1 ="ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz"
    charset2 = "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    for c in s:
        if c in charset2:
            res+=charset1[charset2.index(c)]
        else:
            res+=c
    return res

def b64d(s):
    return b64decode(s.encode()+b'==').decode()

def caesar_decrypt(encrypted_message):
    key = 3
    decrypted_message = ""
    for c in encrypted_message:
        if c in alphabet:
            position = alphabet.find(c)
            new_position = (position - key) % 26
            new_character = alphabet[new_position]
            decrypted_message += new_character
        else:
            decrypted_message += c
    return decrypted_message

output = open('enc.txt','r').read()[:-1]
for i in range(60):
    print(enc_ciphers[int(output[:1])-1],i)
    output = globals()[enc_ciphers[int(output[:1])-1]](output[1:]).strip('=')

    print(output)
```

# KB05

![image](https://user-images.githubusercontent.com/92283038/185405736-4fb46e94-4baf-494b-bf30-7898100ef528.png)

Đề bài có gợi ý cho chúng ta là để ý các packet ICMP và trường Identifiers để tìm flag. Ở đây chúng ta thấy ở trường Identification có chứa các value trông như mã Ascii
trong các packet ping request. Lọc các packet này ra bằng filter ``` ip.dst == 192.168.0.50 ```

![image](https://user-images.githubusercontent.com/92283038/185406350-29f1f3ee-a891-472f-9284-2c50f5cddb40.png)

Giờ mình sẽ thử lấy các giá trị ở cột Identification ra để xem có gì thú vị, vì số lượng packet ít nên mình viết tay ra một file txt và decode bằng python

```py
with open('kb05.txt','r') as file:
    f = file.readlines()
for i in f:
    print(chr(int(i)),end="")
```

Kết quả của script : 
![image](https://user-images.githubusercontent.com/92283038/185406792-30c125d2-075d-4fe5-a992-65949dac7ec7.png)



