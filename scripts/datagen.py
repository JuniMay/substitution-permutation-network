
import random
import subprocess
from typing import List, Tuple

# encryptor executable path
encryptor = './encryptor.exe'

def datagen(key: int, size: int) -> List[Tuple[int, int]]:
    """Generate random data for analysis.
    
    Args:
        key: key to use for encryption
        size: number of plaintext-ciphertext pairs to generate
    """
    
    minimum = 0x0000
    maximum = 0xffff
    
    # generate random plaintexts
    plaintexts = []
    for i in range(size):
        plaintexts.append(random.randint(minimum, maximum))
        
    # encrypt plaintexts
    ciphertexts = []
    for p in plaintexts:
        # 16 bit string padded with 0
        p_str = f'{p:016b}'
        # 32 bit string key
        k_str = f'{key:032b}'
        
        ciphertexts.append(int(subprocess.check_output([encryptor, p_str, k_str]), 2))
    
    # return plaintext-ciphertext pairs
    return list(zip(plaintexts, ciphertexts))

if __name__ == '__main__':
    # generate data
    data = datagen(0b00111010100101001101011000111111, 8000)
    # write data to file
    with open('data.txt', 'w') as f:
        for p, c in data:
            f.write(f'{p} {c}\n')
    