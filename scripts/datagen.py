
import random
import subprocess
import argparse
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
    # generate data from cli argument
    parser = argparse.ArgumentParser()
    parser.add_argument('key', help='key to use for encryption', type=str)
    parser.add_argument('size', help='number of plaintext-ciphertext pairs to generate', type=int)
    parser.add_argument('-o', '--output', help='output file', type=str)
    
    args = parser.parse_args()
    
    key = int(args.key, 2)
    size = args.size
    output = args.output
    
    print(f'Generating {size} plaintext-ciphertext pairs with key {key:032b}')
    
    data = datagen(int(args.key, 2), args.size)
    
    # write data to file
    with open(output, 'w') as f:

        print(f'Writing data to {output}')
        
        for p, c in data:
            f.write(f'{p} {c}\n')
    