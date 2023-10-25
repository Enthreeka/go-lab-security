package user

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

type UsecaseUser interface {
	Authentication(username string, password string, sessionId string) (*User, error)
	StorageReader() (*Storage, error)
	AdminTable(user *User) error
	CreateUser(login string) (*Storage, error)
	UpdatePassword(id int, currentPassword string, newPassword string) error
	GetAccountPageBySession(sessionId string) (*User, *Storage)
}

type userUsecase struct {
}

func NewUserUsecase() UsecaseUser {
	return &userUsecase{}
}

func (u *userUsecase) UpdatePassword(id int, currentPassword string, newPassword string) error {
	storage, err := u.StorageReader()
	if err != nil {
		return err
	}

	for index, user := range storage.User {
		if user.ID == id {
			if user.Password == currentPassword {
				storage.User[index].Password = newPassword
			} else {
				return errors.New("input password in password in db not equal")
			}

			if user.Limit == true {
				if !IsPasswordCorrect(newPassword) {
					return errors.New("new password not correct")
				}
			}
		}
	}

	err = u.storageUpdate(storage)
	if err != nil {
		return err
	}

	return nil
}

func (u *userUsecase) CreateUser(login string) (*Storage, error) {
	storage, err := u.StorageReader()
	if err != nil {
		return nil, err
	}

	for _, allUsers := range storage.User {
		if allUsers.Username == login {
			return nil, errors.New("user exist")
		}
	}

	count := storage.Count + 1
	user := &User{
		ID:       count,
		Username: login,
	}

	err = u.storageWriter(user, storage)
	if err != nil {
		return nil, err
	}

	newUserStorage, err := u.StorageReader()
	if err != nil {
		return nil, err
	}

	return newUserStorage, nil
}

func (u *userUsecase) AdminTable(user *User) error {
	storage, err := u.StorageReader()
	if err != nil {
		return err
	}

	for index, userStorage := range storage.User {
		if userStorage.ID == user.ID {

			user.Admin = userStorage.Admin
			user.Password = userStorage.Password
			if user.ID != 1 {
				if user.Username == "" {
					user.Username = userStorage.Username
				}
			} else {
				user.Username = userStorage.Username
			}

			storage.User[index] = *user
		}
	}

	err = u.storageUpdate(storage)
	if err != nil {
		return err
	}

	return nil
}

func (u *userUsecase) Authentication(username string, password string, sessionId string) (*User, error) {
	storage, err := u.StorageReader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if username == "ADMIN" && errors.Is(err, io.EOF) {
		storage = &Storage{}

		user := &User{
			Username: "ADMIN",
			Admin:    true,
			Block:    false,
			Limit:    false,
			Session:  sessionId,
		}

		err := u.storageWriter(user, storage)
		if err != nil {
			return nil, err
		}

		return user, nil
	}

	if storage != nil {
		for i, user := range storage.User {
			if user.Username == username && user.Password == password {

				//user.Session = sessionId
				//err = u.storageWriter(&user, storage)
				//if err != nil {
				//	return nil, err
				//}

				storage.User[i].Session = sessionId
				err = u.storageUpdate(storage)
				if err != nil {
					return nil, err
				}

				return &user, nil
			}
		}
	}

	return nil, errors.New("not found")
}

func (u *userUsecase) StorageReader() (*Storage, error) {
	file, err := os.Open("storage.json")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	decoder := json.NewDecoder(file)

	users := new(Storage)

	err = decoder.Decode(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *userUsecase) storageWriter(user *User, storage *Storage) error {
	file, err := os.OpenFile("storage.json", os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	storage.Count += 1
	user.ID = storage.Count
	storage.User = append(storage.User, *user)

	storageByte, err := json.MarshalIndent(storage, "", " ")
	if err != nil {
		return err
	}

	_, err = file.Write(storageByte)
	if err != nil {
		return err
	}

	return nil
}

func (u *userUsecase) GetAccountPageBySession(sessionId string) (*User, *Storage) {
	storage, err := u.StorageReader()
	if err != nil {
		return nil, nil
	}

	for _, user := range storage.User {
		if user.Session == sessionId {
			if user.Admin == true {
				return &user, storage
			}
			return &user, nil
		}
	}

	return nil, nil
}

func (u *userUsecase) storageUpdate(storage *Storage) error {
	file, err := os.OpenFile("storage.json", os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	storageByte, err := json.MarshalIndent(storage, "", " ")
	if err != nil {
		return err
	}

	_, err = file.Write(storageByte)
	if err != nil {
		return err
	}

	return nil
}
