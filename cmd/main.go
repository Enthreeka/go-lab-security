package main

import (
	"context"
	"crypto/aes"
	"fmt"
	"github.com/Enthreeka/security/config"
	"github.com/Enthreeka/security/user"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

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

	//mux := http.NewServeMux()

	router := mux.NewRouter()

	router.HandleFunc("/", userHandler.GetLoginPageHandler)
	router.HandleFunc("/login", userHandler.LoginHandler)
	router.HandleFunc("/admin", userHandler.AdminHandler)
	router.HandleFunc("/user/create", userHandler.AdminCreateUserHandler)
	router.HandleFunc("/logout", userHandler.LogoutHandler)
	router.HandleFunc("/update", userHandler.PasswordUpdateHandler)
	router.HandleFunc("/account", userHandler.GetAccountPage)

	router.HandleFunc("/password", userHandler.GetPasswordForEncryptHandler(done))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}
	//go ShutdownProgram(passwordCh, encrypt)
	//
	//go func() {
	//	<-signals
	//
	//	_, cancel := context.WithCancel(context.Background())
	//	defer cancel()
	//
	//	fmt.Println("here shoot")
	//	encrypt.EncryptFile()
	//	os.Remove("storage.json")
	//
	//	close(done)
	//}()

	go func() {
		log.Println("Starting http server: http://localhost:8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	log.Print("Server Started")

	<-done
	log.Print("Server Stopped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		encrypt.EncryptFile()
		os.Remove("storage.json")
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Print("Server Exited Properly")
}

//func ShutdownProgram(passwordCh chan struct{}, encrypt user.Encrypt) {
//	for {
//		select {
//		case <-passwordCh:
//			//
//			//fmt.Println("here")
//			//encrypt.EncryptFile()
//			//os.Remove("storage.json")
//			os.Exit(1)
//		}
//	}
//
//}
