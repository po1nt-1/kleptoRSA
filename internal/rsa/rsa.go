package rsa

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/po1nt-1/kleptoRSA/internal/storage"
)

type PublicKey struct {
	SubjectPublicKeyInfo SubjectPublicKeyInfo `json:"subjectPublicKeyInfo"`
	PKCS10CertRequest    string               `json:"pkcs10CertRequest"`
	Certificate          string               `json:"certificate"`
	PKCS7CertChainPKCS   string               `json:"pkcs7CertChainPKCS"`
}

type SubjectPublicKeyInfo struct {
	PublicExponent *big.Int `json:"publicExponent"`
	N              *big.Int `json:"n"`
}

type PrivateKey struct {
	PrivateExponent *big.Int `json:"privateExponent"`
	Prime1          *big.Int `json:"prime1"`
	Prime2          *big.Int `json:"prime2"`
	Exponent1       *big.Int `json:"exponent1"`
	Exponent2       *big.Int `json:"exponent2"`
	Coefficient     *big.Int `json:"coefficient"`
}

type PlainText struct {
	PlainContent *big.Int `json:"plainContent"`
}

type CipherText struct {
	Version              int                  `json:"version"`
	EncryptedContentInfo EncryptedContentInfo `json:"encryptedContentInfo"`
}

type EncryptedContentInfo struct {
	EncryptedContent                     *big.Int `json:"encryptedContent"`
	ContentType                          string   `json:"contentType"`
	ContentEncryptionAlgorithmIdentifier string   `json:"contentEncryptionAlgorithmIdentifier"`
	Optional                             string   `json:"optional"`
}

func ProbablePrimeMillerRabin(n *big.Int, t int) (isPrime bool, err error) {
	d := new(big.Int).Sub(n, big.NewInt(1))
	s := 0

	for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		d.Rsh(d, 1)
		s++
	}

	a := new(big.Int)
LOOP:
	for i := 0; i < t; i++ {
		a, err = rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		if err != nil {
			return false, fmt.Errorf("rsa/ProbablePrimeMillerRabin: %v", err)
		}
		a.Add(a, big.NewInt(2))

		x := new(big.Int).Exp(a, d, n)
		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
			continue
		}
		for j := 0; j < s-1; j++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(big.NewInt(1)) == 0 {
				return
			}
			if x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
				continue LOOP
			}
		}
		return
	}
	return true, nil
}

func GeneratePrimeNum(k int, ch chan *big.Int, wg *sync.WaitGroup) {
	defer wg.Done()

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(int64(k)), nil)

	i := 0
	for isPrime := false; !isPrime; {
		i++
		p, err := rand.Int(rand.Reader, max)
		if err != nil {
			log.Fatalf("rsa/GeneratePrimeNum: [%v]", err)
		}

		if p.BitLen() != k {
			continue
		}

		p.SetBit(p, 0, 1)

		isPrime, err = ProbablePrimeMillerRabin(p, 100)
		if err != nil {
			log.Fatalf("rsa/GeneratePrimeNum: [%v]", err)
		}

		if i%5000 == 0 {
			log.Print("generating a prime number is too long")
		}

		if isPrime {
			ch <- p
			break
		}
	}
}

func GenerateKeyPair(keyBitLen int) (pub *PublicKey, priv *PrivateKey, err error) {
	firstStep := true
	for firstStep {
		ch := make(chan *big.Int, 2)
		wg := sync.WaitGroup{}
		wg.Add(2)

		go GeneratePrimeNum(keyBitLen/2, ch, &wg)
		go GeneratePrimeNum(keyBitLen/2, ch, &wg)

		wg.Wait()
		close(ch)

		p := <-ch
		q := <-ch

		N := new(big.Int).Mul(p, q)
		if N.BitLen() != keyBitLen {
			continue
		}

		pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
		qMinusOne := new(big.Int).Sub(q, big.NewInt(1))
		phiN := new(big.Int).Mul(pMinusOne, qMinusOne)
		e := big.NewInt(65537)

		d := new(big.Int).ModInverse(e, phiN)
		if d == nil {
			continue
		}
		if d.BitLen() != keyBitLen {
			continue
		}

		pub = &PublicKey{
			SubjectPublicKeyInfo: SubjectPublicKeyInfo{
				N:              N,
				PublicExponent: e,
			},
			PKCS10CertRequest:  "",
			Certificate:        "",
			PKCS7CertChainPKCS: "",
		}
		priv = &PrivateKey{
			PrivateExponent: d,
			Prime1:          p,
			Prime2:          q,
			Exponent1:       new(big.Int).Mod(d, pMinusOne),
			Exponent2:       new(big.Int).Mod(d, qMinusOne),
			Coefficient:     new(big.Int).ModInverse(q, p),
		}

		bKey, err := json.MarshalIndent(pub, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("rsa/GenerateKeyPair: %v", err)
		}
		err = storage.Dump(bKey, fmt.Sprintf("publicKey%d.json", keyBitLen))
		if err != nil {
			return nil, nil, fmt.Errorf("rsa/GenerateKeyPair: %v", err)
		}
		bKey, err = json.MarshalIndent(priv, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("rsa/GenerateKeyPair: %v", err)
		}
		err = storage.Dump(bKey, fmt.Sprintf("privateKey%d.json", keyBitLen))
		if err != nil {
			return nil, nil, fmt.Errorf("rsa/GenerateKeyPair: %v", err)
		}

		firstStep = false
	}
	return
}

func Encode(data string) (hexBigInt *big.Int, err error) {
	hexBigInt, success := new(big.Int).SetString(fmt.Sprintf("%x", data), 16)
	if !success {
		return nil, fmt.Errorf("rsa/Encode: %v", "SetString failure")
	}

	return
}

func Decode(hexBigInt *big.Int) (decoded string, err error) {
	decoded = hexBigInt.Text(16)
	hexBytes, err := hex.DecodeString(decoded)
	if err != nil {
		return "", fmt.Errorf("rsa/Decode: %v", "DecodeString failure")
	}
	decoded = string(hexBytes)

	return
}

func Encrypt(plainText string, pub *PublicKey) (ct *CipherText, err error) {
	ct = &CipherText{
		EncryptedContentInfo: EncryptedContentInfo{
			ContentType:                          "text",
			ContentEncryptionAlgorithmIdentifier: "rsaEncryption",
		},
	}

	encoded, err := Encode(plainText)
	if err != nil {
		return nil, fmt.Errorf("rsa/Encrypt: %v", err)
	}

	// encryption:

	ct.EncryptedContentInfo.EncryptedContent = encoded

	return
}

func Decrypt(cipherText *CipherText, priv *PrivateKey) (plainText string, err error) {
	plainText, err = Decode(cipherText.EncryptedContentInfo.EncryptedContent)
	if err != nil {
		return "", fmt.Errorf("rsa/Decrypt: %v", err)
	}

	return
}
