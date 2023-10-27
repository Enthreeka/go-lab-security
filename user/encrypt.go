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

//var Block = make(map[string]cipher.Block)

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

//func (e *encrypt) EncryptFile() {
//	storage, _ := e.userUsecase.StorageReader()
//
//	storageBytes, err := json.Marshal(storage)
//	if err != nil {
//		fmt.Println("Ошибка при преобразовании JSON:", err)
//		return
//	}
//
//	key := []byte("my-secret-key123")
//
//	// Создайте AES блочный шифр с использованием ключа
//	e.block, err = aes.NewCipher(key)
//	if err != nil {
//		fmt.Println("Ошибка при создании AES блочного шифра:", err)
//		return
//	}
//
//	iv := make([]byte, aes.BlockSize)
//	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
//		fmt.Println("Ошибка при генерации IV:", err)
//		return
//	}
//
//	mode := cipher.NewCBCEncrypter(e.block, iv)
//
//	blockSize := aes.BlockSize
//	padding := blockSize - (len(storageBytes) % blockSize)
//	if padding != 0 {
//		// Добавляем заполнитель
//		for i := 0; i < padding; i++ {
//			storageBytes = append(storageBytes, byte(padding))
//		}
//	}
//
//	encryptedData := make([]byte, len(storageBytes))
//	mode.CryptBlocks(encryptedData, storageBytes)
//
//	// Сохраните IV и зашифрованные данные в файл
//
//	err = os.WriteFile("encrypted.json", append(iv, encryptedData...), 0644)
//	if err != nil {
//		fmt.Println("Ошибка при сохранении зашифрованных данных:", err)
//		return
//	}
//}

func (e *encrypt) EncryptFile() {
	storage, _ := e.userUsecase.StorageReader()

	storageBytes, err := json.Marshal(storage)
	if err != nil {
		fmt.Println("Ошибка при преобразовании JSON:", err)
		return
	}

	//key := []byte("my-secret-key123")
	//
	//// Создайте AES блочный шифр с использованием ключа
	//b, err := aes.NewCipher(key)
	//if err != nil {
	//	fmt.Println("Ошибка при создании AES блочного шифра:", err)
	//	return
	//}
	//
	//Block["block"] = b

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println("Ошибка при генерации IV:", err)
		return
	}

	mode := cipher.NewCBCEncrypter(e.block, iv)

	blockSize := aes.BlockSize
	padding := blockSize - (len(storageBytes) % blockSize)
	if padding != 0 {
		// Добавляем заполнитель
		for i := 0; i < padding; i++ {
			storageBytes = append(storageBytes, byte(padding))
		}
	}

	encryptedData := make([]byte, len(storageBytes))
	mode.CryptBlocks(encryptedData, storageBytes)

	// Сохраните IV и зашифрованные данные в файл

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

	// Извлеките IV и зашифрованные данные
	iv := encryptedDataWithIV[:aes.BlockSize]
	encryptedData := encryptedDataWithIV[aes.BlockSize:]

	// Создайте объект шифра галочки для расшифровки
	mode := cipher.NewCBCDecrypter(e.block, iv)

	// Расшифруйте данные
	decryptedData := make([]byte, len(encryptedData))
	mode.CryptBlocks(decryptedData, encryptedData)

	// Remove the padding from the end of the decrypted data
	padding := int(decryptedData[len(decryptedData)-1])
	decryptedData = decryptedData[:len(decryptedData)-padding]

	// Расшифруйте JSON-данные и преобразуйте их в объект
	var storageByte *Storage

	err = json.Unmarshal(decryptedData, &storageByte)
	if err != nil {
		return err
	}

	err = e.userUsecase.StorageWriter(nil, storageByte)
	if err != nil {
		return err
	}

	//file, err := os.OpenFile("storage.json", os.O_RDWR|os.O_CREATE, 0666)
	//if err != nil {
	//	return err
	//}
	//defer file.Close()
	//
	//storageByte, err := json.MarshalIndent(decryptedData, "", " ")
	//if err != nil {
	//	return err
	//}
	//
	//_, err = file.Write(storageByte)
	//if err != nil {
	//	return err
	//}

	err = os.Remove("encrypted.json")
	if err != nil {
		return err
	}

	//err = json.Unmarshal(decryptedData, &storageByte)
	//if err != nil {
	//	fmt.Println("Ошибка при расшифровке и разборе JSON:", err)
	//	return
	//}
	//
	//err := e.userUsecase.StorageWriter(nil, storageByte)

	// Выведите расшифрованные данные
	//fmt.Printf("Расшифрованные данные: %+v\n", storageByte)

	return nil
}
