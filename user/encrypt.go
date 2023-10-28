package user

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type encrypt struct {
	userUsecase UsecaseUser

	block cipher.Block
}

type Encrypt interface {
	EncryptFile()
	DecryptFile() error
}

func NewEncryptJSON(userUsecase UsecaseUser, block cipher.Block) Encrypt {
	return &encrypt{
		userUsecase: userUsecase,
		block:       block,
	}
}

func (e *encrypt) EncryptFile() {
	storage, _ := e.userUsecase.StorageReader()

	storageBytes, err := json.Marshal(storage)
	if err != nil {
		fmt.Println("Ошибка при преобразовании JSON:", err)
		return
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println("Ошибка при генерации IV:", err)
		return
	}

	mode := cipher.NewCBCEncrypter(e.block, iv)

	blockSize := aes.BlockSize
	padding := blockSize - (len(storageBytes) % blockSize)
	if padding != 0 {
		for i := 0; i < padding; i++ {
			storageBytes = append(storageBytes, byte(padding))
		}
	}

	encryptedData := make([]byte, len(storageBytes))
	mode.CryptBlocks(encryptedData, storageBytes)

	err = os.WriteFile("encrypted.json", append(iv, encryptedData...), 0644)
	if err != nil {
		fmt.Println("Ошибка при сохранении зашифрованных данных:", err)
		return
	}
}

func (e *encrypt) DecryptFile() error {
	encryptedDataWithIV, err := os.ReadFile("encrypted.json")
	if err != nil {
		errText := fmt.Sprintf("Ошибка при чтении зашифрованных данных из файла: %v", err)
		return errors.New(errText)
	}

	iv := encryptedDataWithIV[:aes.BlockSize]
	encryptedData := encryptedDataWithIV[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(e.block, iv)

	decryptedData := make([]byte, len(encryptedData))
	mode.CryptBlocks(decryptedData, encryptedData)

	padding := int(decryptedData[len(decryptedData)-1])
	decryptedData = decryptedData[:len(decryptedData)-padding]

	var storageByte *Storage

	err = json.Unmarshal(decryptedData, &storageByte)
	if err != nil {
		return err
	}

	err = e.userUsecase.StorageWriter(nil, storageByte)
	if err != nil {
		return err
	}

	err = os.Remove("encrypted.json")
	if err != nil {
		return err
	}

	return nil
}
