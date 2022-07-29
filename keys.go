package netrsakeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
)

// init create a key pair os rsa 4096 priv/pub keys
// tuve un error en el cual el marshal en la conversion a PEM para priv y pub son distintos
// https://www.systutorials.com/how-to-generate-rsa-private-and-public-key-pair-in-go-lang/
// https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/
// https://github.com/dgrijalva/jwt-go/blob/master/http_example_test.go
// this reference helped me to get over it.
// Genera las llaves en el directorio indicado
// lo llamaremos con un where del estilo keys/
// las llaves las genera crypt/rand por lo que no sabemos el string
func GenerateKeyPair(where string) {
	pub, priv := "pubRsaKey.pub", "privateRSAKey"
	bitSize := 4096 // equals a 512 bits
	//	log.Print("Iniciando generacion de llaves en: ", where)
	_, err := os.Stat(where)
	//log.Print(err)
	if errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(where, 0744)
		if err != nil {
			log.Fatal("No es posible crear archivo. \n", err)
		}

		log.Print("Carpeta ./keys creada correctamente.")
	}
	_, err = os.Stat(where + priv)
	if errors.Is(err, os.ErrNotExist) {
		privateKey, err := generatePrivateKey(bitSize)
		if err != nil {
			log.Fatal(err)
		}
		// Convertimos la private key a PEM.
		privateKeyBytes := encodePrivateKeyToPem(privateKey)

		publicKeyBytes := encodePublicKeyToPem(privateKey)

		err = writePemToFile(publicKeyBytes, where+pub)
		if err != nil {
			log.Fatal(err)
		}
		err = writePemToFile(privateKeyBytes, where+priv)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("Llaves Generadas Satisfactoriamente.")

	}
	return

}

// Generamos una private key del tamaño establecido con rand number
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Print("Error al Generar private key ", err)
		return nil, err
	}
	// Validamos la llave
	err = privateKey.Validate()
	if err != nil {
		log.Print("Error validating private key: ", err)
		return nil, err
	}
	log.Print("Private key Generated")
	return privateKey, nil

}

// encode Private key from RSA to PEM format
func encodePrivateKeyToPem(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	// privateKey in pem format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// encode Private key from RSA to PEM forma
func encodePublicKeyToPem(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	// Se Convierte en un formato distinto al de la llave publica
	// perdi como 4 horas tras esto OJO...
	privDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Print(err)
	}
	pubBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	// privateKey in pem format
	publicPEM := pem.EncodeToMemory(&pubBlock)

	return publicPEM
}

// Escribe las llaves en formato []byte a un archivo en el destino especificado
func writePemToFile(keyBytes []byte, saveTo string) error {
	log.Print("creando llave ", saveTo)
	err := ioutil.WriteFile(saveTo, keyBytes, 0600)
	if err != nil {
		log.Fatal("Error Al escribir archivo: \n", saveTo, err)
	}
	log.Printf("Key Guardada en archivo %s", saveTo)
	return nil
}
