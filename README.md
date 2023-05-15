## Krypto

Krypto is a Java encryption library that 
includes Korean encryption algorithms such as ARIA, SEED, which have been released through KISA(Korea Internet & Security Agency).

### Getting started

```java
import krypto.Algorithm;
import krypto.AriaAlgorithmFactory;

Algorithm algo = AriaAlgorithmFactory.create("masterkey", 256);
String plain = "Hello";
byte[] cipherText = algo.encrypt(plain.getBytes());
byte[] decryptedText = algo.decrypt(cipherText);
```

### Why Reinvent?

Original Java source codes for ARIA, SEED and LEA from **KISA** are working well.
But they are written in very different ways.
Therefore, it requires some effort to apply their codes into your applications.
Each set of codes could be migrated differently. Additionally,
there are no released artifacts for these codes in Maven.

**Krypto** makes easy to use these algorithms in your modern application
by unifying them with some good patterns and releasing them on Maven.

### Supported Encryption Algorithm

- ARIA: ARIA is a 128 bits block encryption algorithm that was developed through a collaborative effort between Korean academic institutions, government agencies, and research institutes.
  - Block size: 128 bits 
  - Key size: 128, 192, 256 bits
- SEED: SEED is a 128 bits block encryption algorithm.
  - Block size: 128 bits
  - Key size: 128 bits
  - Mode: CBC, ECB (other modes might be added in the future)
- LEA: LEA is a 128 bits block encryption algorithm.
  - Block size: 128 bits
  - Key size: 128, 192, 256 bits
  - Mode: CBC, ECB (other modes might be added in the future)

> **Based on public information from KISA**, The Korea Internet & Security Agency (KISA) does not charge royalties for intellectual property related to the production and sale of products that use SEED, LEA. 
> Public domain source codes are also published from KISA. For more details, please visit [KISA](https://seed.kisa.or.kr/kisa/index.do).

#### References

- Public source codes(ARIA, SEED and LEA): [KISA library](https://seed.kisa.or.kr/kisa/reference/EgovSource.do)
- ARIA: https://seed.kisa.or.kr/kisa/algorithm/EgovAriaInfo.do
- SEED: https://seed.kisa.or.kr/kisa/algorithm/EgovSeedInfo.do
- LEA: https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do