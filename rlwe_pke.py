import numpy as np
from numpy.polynomial import polynomial as poly

def polymul(x: np.ndarray, y: np.ndarray, modulus: int, poly_mod: np.ndarray):
    """Add two polynoms
    Args:
        x, y: two polynoms to be added.
        modulus: coefficient modulus.
        poly_mod: polynomial modulus.
    Returns:
        A polynomial in Z_modulus[X]/(poly_mod).
    """
    return np.int64(
        np.round(poly.polydiv(poly.polymul(x, y) % modulus, poly_mod)[1] % modulus)
    )


def polyadd(x: np.ndarray, y: np.ndarray, modulus: int, poly_mod: np.ndarray):
    """Multiply two polynoms
    Args:
        x, y: two polynoms to be multiplied.
        modulus: coefficient modulus.
        poly_mod: polynomial modulus.
    Returns:
        A polynomial in Z_modulus[X]/(poly_mod).
    """
    return np.int64(
        np.round(poly.polydiv(poly.polyadd(x, y) % modulus, poly_mod)[1] % modulus)
    )

def generate_rlwe_instance(n: int, q: int, poly_mod: np.ndarray, std_deviation: float) -> tuple:

    # Sample polynominal A(x) over a uniform distribution of Rq which means sample the coefficents of the polynominal A(x) over mod q
    A = np.random.randint(0, q, n, dtype=np.int64)

    # Sample polynominal e(x) over a discrete normal distribution of Rq
    e = np.int64(np.random.normal(loc=0, scale=std_deviation, size=n))

    # Sample secret key polynominal sk(x) over a uniform distribution R2, 
    # which means sk(x) has binary coefficents [0,1] since its over mod 2
    sk = np.random.randint(0, 2, n, dtype=np.int64)

    # Compute polynominal b(x) = A(x)*sk(x) + e(x) / (x^n + 1)
    # First compute A(x)*sk(x) / (x^n + 1)
    Ax_sk = np.int64(np.round(poly.polymul(-A,sk) % q))                # perform poly multiplication mod q
    Ax_sk = np.int64(np.round(poly.polydiv(Ax_sk, poly_mod)[1] % q))   # polynominal reduction x^n + 1 mod q

    # Now compute b(x)
    b = np.int64(np.round(poly.polyadd(Ax_sk,-e) % q))        # perform poly addition mod q
    b = np.int64(np.round(poly.polydiv(b, poly_mod)[1] % q))  # polynomnial reduction
    # return rlwe instance that is (A,b) public key and (sk) secret key
    return (A,b),sk



def encrypt(public_key: tuple, n: int, q: int, t: int, poly_mod: np.ndarray, plaintext_message: int) -> tuple:
    """
    Encryption outputs a ciphertext containing two polynominals:
                        ct0=[pk0*u+e1+delta*m]q 
                        ct1=[pk1*u+e2]q
    """

    # first step is to encode integer message into the plaintext space resulting in a plaintext polynominal
    m = np.array([plaintext_message] + [0] * (n - 1), dtype=np.int64) % t
    print(f"Encoded message: {m}")

    # scaling factor, used to scale from plaintext space up to the ciphertext space
    delta = q // t

    # next step is to scale encoded polynominal coefficents in m up to the ciphertext space
    scaled_m = delta * m  % q

    # Sample random E1(x) and E2(x) polynominal coefficents over a discrete normal distribution of size n-1 
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
    # pk0_u = np.int64(np.polydiv(np.polymul(public_key[0], u) % q, poly_mod)[1] % q)
    # pk0_u = np.int64(np.round(poly.polymul(public_key[0],u) % q))
    # pk0_u = np.int64(np.round(poly.polydiv(pk0_u,poly_mod)[1] % q))

    # delta_m = np.int64(np.round(poly.polymul(scaled_m, m) % q))
    # delta_m = np.int64(np.round(poly.polydiv(delta_m,poly_mod)[1] % q))

    # ct0 = np.int64(np.round(poly.polyadd(pk0_u,e1) % q))
    # ct0 = np.int64(np.round(poly.polydiv(ct0, poly_mod)[1] % q))

    # ct0 = np.int64(np.round(poly.polyadd(ct0,delta_m) % q))
    # ct0 = np.int64(np.round(poly.polydiv(ct0,poly_mod)[1] % q))
    
    # # Compute ct1 = [pk1 * u + e2]
    # # 1. Compute pk1_u = pk1 * u mod (X^n+1)
    # # 2. Compute ct1 = pk1_u + e2 mod (X^n+1)
    # pk1_u = np.int64(np.round(poly.polymul(public_key[1], u) % q))
    # pk1_u = np.int64(np.round(np.round(poly.polydiv(pk1_u,poly_mod)[1] % q)))
    # ct1 = np.int64(np.round(poly.polyadd(pk1_u,e2) % q))
    # ct1 = np.int64(np.round(poly.polydiv(ct1,poly_mod)[1] % q))

    # sanity check
    ct0 = polyadd(
            polyadd(
                polymul(public_key[0], u, q, poly_mod),
                e1, q, poly_mod),
            scaled_m, q, poly_mod
        )
    ct1 = polyadd(
            polymul(public_key[1], u, q, poly_mod),
            e2, q, poly_mod
        )

    # pk1_u = np.int64(np.polydiv(np.polymul(public_key[1], u) % q, poly_mod)[1] % q)
    # ct1 = np.int64(np.polydiv(np.polyadd(pk1_u,e2) % q, poly_mod)[1] % q)
    
    return (ct0, ct1)


def decrypt(secret_key: np.ndarray, n: int, q: int, t: int, poly_mod: np.ndarray, ciphertext: np.ndarray):
    """
    Decrypt a ciphertext
    [⌊1δ⋅[ct0+ct1⋅sk]q⌉]t=[⌊[m+1δ⋅errors]q⌉]t
    """
    scaled_pt = polyadd(
            polymul(ciphertext[1], secret_key, q, poly_mod),
            ciphertext[0], q, poly_mod
    )

    # ct1_sk = np.int64(np.round(poly.polymul(ciphertext[1], secret_key) % q))
    # ct1_sk = np.int64(np.round(np.polydiv(ct1_sk,poly_mod)[1] % q))

    # scaled_pt = np.int64(np.round(poly.polyadd(ciphertext[0], ct1_sk) % q))
    # scaled_pt = np.int64(np.round(poly.polydiv(scaled_pt, poly_mod)[1] % q))

    decrypted_poly = np.round(scaled_pt * t / q) % t
    return int(decrypted_poly[0])


if __name__ == "__main__":

    # set RLWE parameters
    n = 2**4            # polynomial degree
    q = 2**15           # ciphertext modulus
    t = 2**8            # plaintext modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])  # polynomial modulus, this gives (x^15 + 1)
    sigma = 2.0         # std deviation of the noise distribution

    plaintext = 200

    print(f"Polynominal modulus: {poly_mod}")

    public_key, secret_key = generate_rlwe_instance(n,q,poly_mod,sigma)
    print(f"(public key: {public_key}")
    print(f"secret key: {secret_key}")

    ciphertext = encrypt(public_key, n, q, t, poly_mod, plaintext)
    print(f"ciphertext: {ciphertext}")

    result = decrypt(secret_key,n,q,t,poly_mod,ciphertext)
    print(f"result: {result}")

    # print(f"ct0: {ct0}")
    # print(f"ct1: {ct1}")




