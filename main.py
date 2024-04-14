import numpy as np

# set LWE parameters
n = 4         # security parameter
N = 7         # sample size
q = 31          # modulus
sigma = 1.0      # std deviation of the noise distribution

plaintext_message = np.random.randint(0,2,20)
print(f"plaintext: {plaintext_message}\n")

# generate LWE keypair (pk,sk)  -> ((A,b),sk)    
def generate_lwe_instance(q,n,N,sigma):

    # Create A matrix of uniform distribution over Zq of size Nxn
    A = np.random.randint(0, q, size=(N, n))

    # Create noise vector, sample error distribution from a discrete gaussian distribution over Zq of size N
    e = np.random.normal(loc=0, scale=sigma, size=N)
    e = np.round(e)
    e = np.mod(e,q)
    e = e.astype(int)

    # Create a random secret vector of size n over [0,q-1]
    sk = np.random.randint(0, q-1,size=n)

    # Compute As
    As = np.dot(A,sk)

    # Compute b = (As + e) mod q
    b = np.mod(As + e,q)

    # return public key (A,b) and secret key (sk)
    return A,b,sk


# Encrypt each bit message m within the set {0,1}
def encrypt(data, A, b, q, N):
    
    # Sample a random binary vector r{0,1} of size N 
    r = np.random.randint(0,2,N)

    # Compute u=AT*r  (AT is A matrix transposed)
    u = np.dot(np.transpose(A), r)

    # Compute v=bTr+⌊q/2⌋m 
    v = np.dot(np.transpose(b),r) + np.dot(np.round(q/2),data)

    # Output the ciphertext c=(u,v)
    return u,v


# decrypt ciphertext and compare plaintext to decrypted
def decrypt(u,v,secret_key,q):

    # Compute v' = sT * u
    v_ = np.dot(np.transpose(secret_key), u)

    # Compute d = v - v'
    d = v - v_

    # Compute m = [2d/q] mod 2, where ⌈x⌋ denotes rounding x to the nearest integer with ties being rounded up 
    # (note x is not reduced modulo q)
    m = np.mod(np.round((2*d)/q),2)
    return m



def main():

    print(f"message: {plaintext_message} \n")

    # generate lwe instance which is a public key (A,b) and private key (secret_key)
    a,b,secret_key = generate_lwe_instance(q,n,N,sigma)

    # encrypt message which outputs a tuple
    u,v = encrypt(plaintext_message,a,b,q,N)
    print("ciphertext: ")
    print(f"u: {u}\n")
    print(f"v: {v}\n")

    # decrypt message
    m = decrypt(u,v,secret_key,q)
    print(f"decrypted: {m}\n")

    # compare plaintext and decrypted message
    if np.array_equal(m,plaintext_message):
        print("Successful decryption")
    else:
        print("Insuccess decryption")


if __name__ == "__main__":
    main()