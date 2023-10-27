package main

import (
	"crypto/aes"
	"fmt"
	"github.com/Enthreeka/security/config"
	"github.com/Enthreeka/security/user"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

//func init() {
//	cfg, err := config.New()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	userUsecase := user.NewUserUsecase()
//
//	block, err := aes.NewCipher([]byte(cfg.SecretKey.DecryptKey))
//	if err != nil {
//		fmt.Println("Ошибка при создании AES блочного шифра:", err)
//		return
//	}
//
//	encrypt := user.NewEncryptJSON(userUsecase, block)
//
//	encrypt.EncryptFile()
//
//}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	signalCh := make(chan struct{})

	var store = sessions.NewCookieStore([]byte("your-secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}

	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	userUsecase := user.NewUserUsecase()

	block, err := aes.NewCipher([]byte(cfg.SecretKey.DecryptKey))
	if err != nil {
		fmt.Println("Ошибка при создании AES блочного шифра:", err)
		return
	}

	encrypt := user.NewEncryptJSON(userUsecase, block)

	userHandler := user.NewUserHandler(userUsecase, encrypt, store, cfg)

	mux := http.NewServeMux()

	mux.HandleFunc("/", userHandler.GetLoginPageHandler)
	mux.HandleFunc("/login", userHandler.LoginHandler)
	mux.HandleFunc("/admin", userHandler.AdminHandler)
	mux.HandleFunc("/user/create", userHandler.AdminCreateUserHandler)
	mux.HandleFunc("/logout", userHandler.LogoutHandler)
	mux.HandleFunc("/update", userHandler.PasswordUpdateHandler)
	mux.HandleFunc("/account", userHandler.GetAccountPage)

	mux.HandleFunc("/password", userHandler.GetPasswordForEncryptHandler(signalCh))

	go ShutdownProgram(signalCh, encrypt)

	go func() {
		<-signals

		close(signals)
	}()

	log.Println("Starting http server: http://localhost:8080")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("%v", err)
	}
}

func ShutdownProgram(signal chan struct{}, encrypt user.Encrypt) {
	for {
		select {
		case <-signal:
			fmt.Println("here")
			encrypt.EncryptFile()
			os.Remove("storage.json")
			os.Exit(1)
		}
	}

}
