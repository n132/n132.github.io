# Prologue

We have learned Asymmetric Encryption in RSA part. This module would go through RSA and El-Gamal.

# Definitions

## Public Key Encryption

The Asymmetric Encryption consists of a triple of efficient algorithms `(KG,E,D)`.

(Satisfies `correctness` and `security`)

- KG: Key Generator, returns `public-key PK` and `private-key SK`
- E: the encryption algorithm, `E(m,PK) -> c`
- D: the decryption algorithm, `D(c,SK) -> m`

## IND (for Asymmetric Encryption)

Definition:

- An Asymmetric Encryption satisfies IND, if the adversary can’t take advantage even if PK, m(0), m(1) and c are given.

If an Asymmetric Encryption satisfies IND, the adversary can’t take advantage in the presence of an eavesdropper.

## IND-CPA/CMA

Chosen Plaintext/Message Attack

Definition:


- An Asymmetric Encryption satisfies IND-CPA, if the adversary can’t take advantage even if PK, m(0), m(1) and c are given + the adversary  could access the `E`.

Because the encryption encryption algorithm is open to the public so if a public key encryption scheme satisfies IND, it satisfies IND-CPA, too.

Tip: Encrypting each bit of a message using an IND-CPA secure scheme
results in an IND-CPA secure encryption of the message

## IND-CCA

Chosen Ciphertext Attack

Definetion:

- Asymmetric Encryption satisfies IND-CPA, if the adversary can’t take advantage even if PK, m(0), m(1) and c are given + the adversary could access to the `E` and `D` (can’t query `c`).

(I think it’s insane. And most of public key encryption can’t satisfies it.)

# A Generic PKE Construction
> Lecture 10 Page14

## Scheme
---
f: OW function, P: hard-core Predicate, x: a random number 

1. Alice: $y = f(x), d = P(x) \bigoplus b$
2. Bob: $f^{-1}(y)\rightarrow x , P(x) \bigoplus d \rightarrow b$
---

## Security

- This scheme satisfies IND-CPA.
- `f` and `P` could use the hardness of RSA.
- This scheme doesn't satiesfies IND-CCA; We could construct a IND-CCA scheme by `+Zero-Knowledge` 

# Text Book RSA

## Scheme
- KG 
---
KG: (p and q are big same-length prime)

$n= p*q, ed = 1 mod\quad phi(n)$

$PK\rightarrow(e,n), SK\rightarrow(d,n)$ 

---
- $E\leftarrow c=m^emod\quad n$
- $D\leftarrow m=c^dmod\quad n$ 

## Security

- **Doesn't** satisfies IND and IND-CPA
- Because it's deterministic, so if the adversary have the plaintext and the scheme, he could use `PK` to encrypt `m(0),m(1)` and compare the results and c.

Satisfies Randomness/One-Wayness under RSA assumption

# Padding RSA

## Scheme
Add randomness to the text book RSA. r is a randomnumber and `|` means concatenation.

- KG: Same as Text-Book-RSA
- $E\leftarrow c=(r|m)^emod\quad n$
- $D\leftarrow m=c^dmod\quad n$ 


## Security

- **Doesn't** satisfies IND-CCA
- Satisfies IND and IND-CPA

Why **Doesn't** satisfies IND-CCA? (e.g. TB-RSA)

Attack

1. Query $c'\leftarrow c*r^e$ and get the result `m'`
2. $m'=r^{ed} * c^{d} = r^1*m^{1}$
3. $m=m'r^{-1}$

# OAEP RSA
## Scheme
To be honest, I don't know the details.

[OAEP RSA](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)

## Security
- Satisfies IND-CPA
- Conditinal IND-CCA-Secure
- OAEP+ Satisfies IND-CCA

# El-gamal

## Scheme

---
Prime: p,q(p=2q+1); Cyclic Group: `<g>`

Private Key: x

Public Key: $(p,q,g,h)$ , $h=g^x$

E: $u \leftarrow g^r, v\leftarrow m*h^r$

D: $m\leftarrow v/u^x$

---

## Security
- Satisfies IND-CPA
- **Doesn't** satisfies IND-CCA

# Cramer-Shoup Scheme

## Scheme 
I don't know this [scheme](https://en.wikipedia.org/wiki/Cramer%E2%80%93Shoup_cryptosystem), too.

## Security
- Satisfies IND-CCA

# DL/Factoring Assumption

## DL assumption (informal)

Can't get `x` from $g^x$ in Cyclic Group `<g>`. 

## DDH assumption (informal)

Can't distinguish $(g,g^x,g^y,g^{xy})$ and $(g,g^x,g^y,g^z)$.

## Theorem
- If DL is easy, DDL is easy.
- If DDL is hard, DL is hard.
- If F is easy, RSA is eay.
- If RSA is hard, F is hard.

# Misc
- Public-key Encryption's Implementation Settings (Page31)
- Public-key Encryption's Implementation Pitfalls (Page32)
