package config

import (
	"github.com/joho/godotenv"
	"os"
)

type (
	Config struct {
		SecretKey SecretKey
	}

	SecretKey struct {
		DecryptKey string
	}
)

func New() (*Config, error) {
	err := godotenv.Load("encrypt.env")
	if err != nil {
		return nil, err
	}

	config := &Config{
		SecretKey: SecretKey{
			DecryptKey: os.Getenv("DECRYPT_KEY"),
		},
	}

	return config, nil
}
