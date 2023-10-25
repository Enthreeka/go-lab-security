package main

import (
	"github.com/Enthreeka/security/user"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
)

func main() {
	var store = sessions.NewCookieStore([]byte("your-secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}

	userUsecase := user.NewUserUsecase()
	userHandler := user.NewUserHandler(userUsecase, store)

	mux := http.NewServeMux()

	mux.HandleFunc("/", userHandler.GetLoginPageHandler)
	mux.HandleFunc("/login", userHandler.LoginHandler)
	mux.HandleFunc("/admin", userHandler.AdminHandler)
	mux.HandleFunc("/user/create", userHandler.AdminCreateUserHandler)
	mux.HandleFunc("/logout", userHandler.LogoutHandler)
	mux.HandleFunc("/update", userHandler.PasswordUpdateHandler)
	mux.HandleFunc("/account", userHandler.GetAccountPage)

	log.Println("Starting http server: http://localhost:8080")
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("%v", err)
	}
}
