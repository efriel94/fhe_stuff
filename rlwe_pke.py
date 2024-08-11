import numpy as np

def polymul(x, y, modulus, poly_mod):
    return np.int64(
        np.round(np.polydiv(np.polymul(x, y) % modulus, poly_mod)[1] % modulus)
    )

def polyadd(x, y, modulus, poly_mod):
   return np.int64(
        np.round(np.polydiv(np.polyadd(x, y) % modulus, poly_mod)[1] % modulus)
    ) 


def generate_rlwe_instance(polynominal_degree:int, ciphertext_modulus:int, std_deviation: float) -> tuple:

    # Sample polynominal A(x) over a uniform distribution of Rq which means sample the coefficents of the polynominal A(x) over mod q
    A = np.random.randint(0, ciphertext_modulus, polynominal_degree, dtype=np.int64)

    # Sample polynominal e(x) over a discrete normal distribution of Rq
    e = np.int64(np.random.normal(loc=0, scale=std_deviation, size=polynominal_degree))
    #e = np.mod(e,q)

    # Sample secret key polynominal sk(x) over a uniform distribution R2, 
    # which means sk(x) has binary coefficents [0,1] since its over mod 2
    sk = np.random.randint(0, 2, polynominal_degree, dtype=np.int64)

    # Compute polynominal b(x) = A(x)*sk(x) + e(x) / (x^n + 1)
    # First compute A(x)*sk(x) / (x^n + 1)
    Ax_sk = np.int64(
        np.round(np.polydiv(np.polymul(A,sk) % ciphertext_modulus, poly_mod)[1] % ciphertext_modulus)
        )

    # Now compute b(x)
    b = np.int64(
        #np.round(polyadd(Ax_sk,e,ciphertext_modulus))
        np.round(np.polydiv(np.polyadd(Ax_sk,e) % ciphertext_modulus, poly_mod)[1] % ciphertext_modulus)
    ) 

    # return rlwe instance that is (A,b) public key and (sk) secret key
    return (A,b),sk



def encrypt(public_key:tuple, n:int, q:int, t:int, poly_mod:np.array, plaintext_message:int) -> tuple:
    """
    Encryption outputs a ciphertext containing two polynominals:
                        ct0=[pk0*u+e1+delta*m]q 
                        ct1=[pk1*u+e2]q
    """

    # first step is to encode integer message into the plaintext space resulting in a plaintext polynominal
    m = np.array([plaintext_message] + [0] * (n - 1), dtype=np.int64) % t
    print(f"encoded m: {m}")

    # scaling factor, used to scale from plaintext space up to the ciphertext space
    delta = q // t

    # next step is to scale encoded polynominal coefficents in m up to the ciphertext space
    scaled_m = delta * m  % q

    # Sample random E1(x) and E2(x) polynominal coefficents over a discrete normal distribution 
    e1 = np.int64(np.random.normal(loc=0, scale=sigma, size=n))
    e2 = np.int64(np.random.normal(loc=0, scale=sigma, size=n))

    # Sample random U(x) polynomial binary coefficents over a uniform distribution
    u = np.random.randint(0, 2, n, dtype=np.int64)

    # ct0=[pk0⋅u+e1+δ⋅m]q
    # ct1=[pk1⋅u+e2]q

    # Compute ct0 = [pk0 * u + e1 + delta*message]
    # 1. Compute pk0_u = pk0 * u / (X^n+1)
    # 2. Compute d_m = delta * message / (X^n+1)
    # 3. Compute ct0 = pk0_u + e1 + d_m / (X^n+1)
    pk0_u = np.int64(
        np.round(np.polydiv(np.polymul(public_key[0], u) % q, poly_mod)[1] % q)
    )
    delta_m =  np.int64(
        np.round(np.polydiv(np.polymul(scaled_m, plaintext_message) % q, poly_mod)[1] % q)
    )
    ct0 = np.int64(
    np.round(np.polydiv(np.polyadd(np.polyadd(pk0_u, e1), delta_m) % q, poly_mod)[1] % q)
    )
    
    # Compute ct1 = [pk1 * u + e2]
    # 1. Compute pk1_u = pk1 * u mod (X^n+1)
    # 2. Compute ct1 = pk1_u + e2 mod (X^n+1)
    pk1_u = np.int64(
        np.round(np.polydiv(np.polymul(public_key[1], u) % q, poly_mod)[1] % q)
    )
    ct1 = np.int64(
        np.round(np.polydiv(np.polyadd(pk1_u,e2) % q, poly_mod)[1] % q)
    )

    print(f"ct0 : {ct0}")
    print(f"ct1 : {ct1}")
    
    return (ct0, ct1)


def decrypt(secret_key:np.array, n:int, q:int, t:int, poly_mod:np.array, ciphertext:np.array):
    


if __name__ == "__main__":

    # set RLWE parameters
    n = 2**4            # polynomial degree
    q = 2**15           # ciphertext modulus
    t = 2**8            # plaintext modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])  # polynomial modulus, this gives (x^15 + 1)
    sigma = 3.0         # std deviation of the noise distribution

    plaintext = 80

    print(f"Polynominal modulus: {poly_mod}")

    public_key, secret_key = generate_rlwe_instance(n,q,sigma)

    ct0, ct1 = encrypt(public_key, n, q, t, poly_mod, plaintext)
    print(f"(A) public key: {public_key[0]}")
    print(f"(b) public key: {public_key[1]}")
    print(f"secret key: {secret_key}")

    print(f"ct0: {ct0}")
    print(f"ct1: {ct1}")




