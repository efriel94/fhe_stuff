import numpy as np
from numpy.polynomial import polynomial as poly

def keygen(n: int, q: int, poly_mod: np.ndarray, std_deviation: float) -> tuple:

    # Sample polynominal A(x) over a uniform distribution of Rq which means sample the coefficents of the polynominal A(x) over mod q
    A = np.random.randint(0, q, n, dtype=np.int64)

    # Sample polynominal e(x) over a discrete normal distribution of Rq
    e = np.int64(np.random.normal(loc=0, scale=std_deviation, size=n))

    # Sample secret key polynominal sk(x) over a binary distribution 
    sk = np.random.randint(0, 2, n, dtype=np.int64)

    # Compute polynominal b(x) = -(A(x)*sk(x) + e(x)) / (x^n + 1)
    # First compute A(x)*sk(x) / (x^n + 1)
    Ax_sk = np.int64(np.round(poly.polymul(-A,sk) % q))                # perform poly multiplication mod q
    Ax_sk = np.int64(np.round(poly.polydiv(Ax_sk, poly_mod)[1] % q))   # polynominal reduction x^n + 1 mod q

    # Now compute b(x)
    b = np.int64(np.round(poly.polyadd(Ax_sk,-e) % q))        # perform poly addition mod q
    b = np.int64(np.round(poly.polydiv(b, poly_mod)[1] % q))  # polynomnial reduction
    # return rlwe instance that is (A,b) public key and (sk) secret key
    return (b,A),sk



def encrypt(sigma: float, public_key: tuple, n: int, q: int, t: int, poly_mod: np.ndarray, plaintext_message: int) -> tuple:
    """
    Encryption outputs a ciphertext containing two polynominals:
                        ct0=[pk0*u+e1+delta*m]q 
                        ct1=[pk1*u+e2]q
    """

    # first step is to encode integer message into the plaintext space resulting in a plaintext polynominal
    m = np.array([plaintext_message] + [0] * (n - 1), dtype=np.int64) % t
    print(f"Encoded message: {m}")

    # scaling factor, used to scale between plaintext space and ciphertext space
    delta = q // t

    # next step is to scale encoded polynominal coefficents in m up to the ciphertext space
    scaled_m = delta * m  % q

    # Sample random E1(x) and E2(x) polynominal coefficents over a discrete normal distribution of size n-1 
    e1 = np.int64(np.random.normal(loc=0, scale=sigma, size=n))
    e2 = np.int64(np.random.normal(loc=0, scale=sigma, size=n))

    # Sample random U(x) polynomial binary coefficents over a uniform distribution
    u = np.random.randint(0, 2, n, dtype=np.int64)
    
    # Compute ct0 = [pk0 * u + e1 + scaled_m]
    # 1. Compute pk0_u = pk0 * u / (X^n+1)
    # 2. Compute ct0 = pk0_u + e1 + scaled_m / (X^n+1)
    pk0_u = np.int64(np.round(poly.polydiv(poly.polymul(public_key[0], u) % q, poly_mod)[1] % q))
    ct0 = np.int64(np.round(poly.polydiv(poly.polyadd(pk0_u,e1) % q, poly_mod)[1] % q))
    ct0 = np.int64(np.round(poly.polydiv(poly.polyadd(ct0,scaled_m) % q, poly_mod)[1] % q))
    
    # Compute ct1 = [pk1 * u + e2]
    # 1. Compute pk1_u = pk1 * u / (X^n+1)
    # 2. Compute ct1 = pk1_u + e2 / (X^n+1)
    pk1_u = np.int64(np.round(poly.polydiv(poly.polymul(public_key[1], u) % q, poly_mod)[1] % q))
    ct1 = np.int64(np.round(poly.polydiv(poly.polyadd(pk1_u,e2) % q, poly_mod)[1] % q))
    
    return (ct0, ct1)


def decrypt(secret_key: np.ndarray, n: int, q: int, t: int, poly_mod: np.ndarray, ciphertext: np.ndarray):
    """
    Decrypt a ciphertext
    scaled_plaintext = [[ct0 + ct1 * sk]q]t
    """

    ct1_sk = np.int64(np.round(poly.polydiv(poly.polymul(ciphertext[1], secret_key) % q, poly_mod)[1] % q))
    scaled_pt = np.int64(np.round(poly.polydiv(np.polyadd(ciphertext[0], ct1_sk) % q, poly_mod)[1] % q))

    decrypted_poly = np.int64(np.round(scaled_pt * t / q)) % t
    return int(decrypted_poly[0])


if __name__ == "__main__":

    # set RLWE parameters
    n = 2**4            # polynomial degree
    q = 2**15           # ciphertext modulus
    t = 2**8           # plaintext modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])  # polynomial modulus, this gives (x^15 + 1)
    sigma = 2.0         # std deviation of the noise distribution

    plaintext = 200

    print(f"Polynominal modulus: {poly_mod}")

    public_key, secret_key = keygen(n,q,poly_mod,sigma)
    print(f"(public key: {public_key}")
    print(f"secret key: {secret_key}\n")

    encrypted_result = encrypt(sigma, public_key, n, q, t, poly_mod, plaintext) # returns a tuple of ciphertexts
    print(f"ciphertext: {plaintext}")
    print(f"\tct0: {encrypted_result[0]}")
    print(f"\tct0: {encrypted_result[1]}")

    result = decrypt(secret_key,n,q,t,poly_mod,encrypted_result)
    print(f"decrypted result: {plaintext}: {result}")




