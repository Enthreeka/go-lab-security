package user

import (
	"regexp"
)

type Storage struct {
	Count int    `json:"count"`
	User  []User `json:"users"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`

	Session string `json:"session"`

	Admin bool `json:"admin"`
	Limit bool `json:"limit"`
	Block bool `json:"block"`
}

// IsPasswordCorrect - 17. Наличие букв, знаков препинания и знаков арифметических операций.
func IsPasswordCorrect(password string) bool {
	regex := regexp.MustCompile(`[a-zA-Z]+.*[\p{P}\p{S}]`)

	if !regex.MatchString(password) {
		return false
	}

	return true
}
