import numpy as np

# set LWE parameters
n = 4         # security parameter
N = 7         # sample size
q = 31        # modulus
sigma = 1.0   # std deviation of the noise distribution


# Create LWE keypair (public_key,secret_key)     
def generate_lwe_instance(q:int, n:int, N:int, sigma:float) -> tuple:

    # Sample a random A matrix of uniform distribution over Zq of size Nxn
    A = np.random.uniform(0, q, size=(N, n)).astype(int)

    # Sample a random error vector from a discrete gaussian distribution over Zq of size N
    # Convert to int
    e = np.random.normal(loc=0, scale=sigma, size=N)
    e = np.round(e)
    e = np.mod(e,q)
    e = e.astype(int)

    # Sample a random secret vector of uniform distribution of size n over [0,q-1]
    sk = np.random.uniform(0, q-1,size=n).astype(int)

    # Compute As
    As = np.dot(A,sk)

    # Compute b = (As + e) mod q
    b = np.mod(As + e,q)

    # return public key (A,b) and secret key (sk)
    return A,b,sk


# Encrypt each message bit
def encrypt(data: np.ndarray, A: np.ndarray, b: np.ndarray, q: int, N: int) -> tuple:
    
    # Sample a random binary vector r{0,1} of size N 
    r = np.random.randint(0,2,N)

    # Compute u=AT*r  (AT is A matrix transposed)
    u = np.dot(np.transpose(A), r)

    # Compute v=bTr+⌊q/2⌋m 
    v = np.dot(np.transpose(b),r) + np.dot(np.round(q/2),data)

    # Output the ciphertext c=(u,v)
    return u,v


# Decrypt ciphertext
def decrypt(u:np.ndarray, v:np.ndarray, secret_key:np.ndarray, q:int) -> np.ndarray:

    # Compute v' = sT * u
    v_ = np.dot(np.transpose(secret_key), u)

    # Compute d = v - v'
    d = v - v_

    # Compute m = [2d/q] mod 2, where ⌈x⌋ denotes rounding x to the nearest integer with ties being rounded up 
    # (note x is not reduced modulo q)
    m = np.mod(np.round((2*d)/q),2)
    return m

# Convert string to numpy.ndarray
def convert_string_to_numpy(data: str) -> np.ndarray:

    # Convert string to binary representation
    binary_string = ''.join(format(ord(char), '08b') for char in data)
    
    # Convert binary string to NumPy array of 1's and 0's
    binary_array = np.array([int(bit) for bit in binary_string])
    return binary_array


# Convert numpy.ndarray to letters
def convert_numpy_to_string(data: np.ndarray) -> str:
    binary_string = ''.join(map(str, data))
    output_string = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return output_string




def main():

    # plaintext message to encrypt
    plaintext_message = "My name is Emmet"
    plaintext_message_bytes = convert_string_to_numpy(plaintext_message)   # convert to bytearray
    print(f"Plaintext message: {plaintext_message}\n")

    # generate lwe instance which is a public key (A,b) and private key (secret_key)
    a,b,secret_key = generate_lwe_instance(q,n,N,sigma)

    # encrypt message
    u,v = encrypt(plaintext_message_bytes,a,b,q,N)
    print("ciphertext: ")
    print(f"u: {u}\n")
    print(f"v: {v}\n")

    # decrypt message
    m_np = decrypt(u,v,secret_key,q)
    m_int = m_np.astype(int)
    decrypted_msg = convert_numpy_to_string(m_int)
    print(f"Decrypted message: {decrypted_msg}\n")

    # compare plaintext and decrypted message
    if np.array_equal(m_np,plaintext_message_bytes):
        print("Successful decryption\n")
    else:
        print("Insuccess decryption")


if __name__ == "__main__":
    main()