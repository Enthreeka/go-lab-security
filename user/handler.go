package user

import (
	"fmt"
	"github.com/Enthreeka/security/config"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"syscall"
)

type userHandler struct {
	uh      UsecaseUser
	encrypt Encrypt
	store   *sessions.CookieStore

	cfg *config.Config

	securityPasswordCheck map[string]bool
}

func NewUserHandler(uh UsecaseUser, encr Encrypt, store *sessions.CookieStore, cfg *config.Config) *userHandler {
	return &userHandler{
		uh:                    uh,
		encrypt:               encr,
		store:                 store,
		cfg:                   cfg,
		securityPasswordCheck: make(map[string]bool),
	}

}

func (u *userHandler) PasswordUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		currentPassword := r.FormValue("currentPassword")
		newPassword := r.FormValue("newPassword")
		id := getID(r)
		log.Printf("get update password:id-[%d],currentPassword-[%s],newPassword-[%s]\n", id, currentPassword, newPassword)

		err := u.uh.UpdatePassword(id, currentPassword, newPassword)
		if err != nil {
			log.Println(err)
			if err.Error() == "input password in password in db not equal" {
				w.WriteHeader(http.StatusNotFound)
				return
			} else if err.Error() == "new password not correct" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusOK)
	}
}

func (u *userHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		session, _ := u.store.Get(r, "session.id")
		session.Values["authenticated"] = false
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (u *userHandler) AdminCreateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		login := r.FormValue("login")

		id := getID(r)
		if login == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		storage, err := u.uh.CreateUser(login)
		if err != nil {
			log.Println(err)
			if err.Error() == "user exist" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		user := new(User)
		for _, userList := range storage.User {
			if userList.ID == id {
				user = &userList
			}
		}

		data := struct {
			CurrentUser *User
			AllUsers    *Storage
		}{
			CurrentUser: user,
			AllUsers:    storage,
		}

		u.GetAccountPageHandler(w, r, data)
	}
}

func updateUser(id int, block string, limit string) *User {
	parse := func(str string) bool {
		return str == "true"
	}

	user := &User{
		ID:    id,
		Block: parse(block),
		Limit: parse(limit),
	}

	return user
}

func (u *userHandler) AdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		id := r.FormValue("id")
		login := r.FormValue("login")
		block := r.FormValue("block")
		limit := r.FormValue("limit")
		log.Printf("get from admin panel:id-[%s],login-[%s],block-[%s],limit-[%s]\n", id, login, block, limit)

		idInt, err := strconv.Atoi(id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
		}

		user := updateUser(idInt, block, limit)

		if idInt != 1 {
			user.Username = login
		}

		err = u.uh.AdminTable(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
		}
	}
}

func (u *userHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	log.Printf("get username - [%s]\n", username)
	password := r.FormValue("password")
	log.Printf("get password - [%s]\n", password)

	if r.Method == http.MethodPost {
		sessionId := uuid.New().String()

		user, err := u.uh.Authentication(username, password, sessionId)
		if err != nil {
			if err.Error() == "not found" {
				http.Error(w, "user not found", http.StatusNotFound)
			}
			log.Println(err)
		}

		if user.Block == true {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		session, err := u.store.Get(r, "session.id")
		if err != nil {
			fmt.Println(err)
		}
		session.Values["authenticated"] = true
		session.Values["sessionID"] = sessionId
		session.Save(r, w)

		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}

func (u *userHandler) GetAccountPage(w http.ResponseWriter, r *http.Request) {
	session, _ := u.store.Get(r, "session.id")

	if (session.Values["authenticated"] != nil) && session.Values["authenticated"] != false {
		sessionId := session.Values["sessionID"]

		user, storage := u.uh.GetAccountPageBySession(sessionId.(string))

		data := struct {
			CurrentUser *User
			AllUsers    *Storage
		}{
			CurrentUser: user,
			AllUsers:    storage,
		}

		u.GetAccountPageHandler(w, r, data)
	}
}

func (u *userHandler) GetAccountPageHandler(w http.ResponseWriter, r *http.Request, data any) {
	parseTemplate(w, "./templates/account.html", data)
}

func (u *userHandler) GetLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Check": u.securityPasswordCheck,
	}

	parseTemplate(w, "./templates/login.html", data)
}

func parseTemplate(w http.ResponseWriter, path string, data any) {
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		fmt.Printf("%v", err)
	}

	tmpl.Execute(w, data)
}

func getID(r *http.Request) int {
	id := r.FormValue("id")
	idInt, _ := strconv.Atoi(id)

	return idInt
}

func (u *userHandler) GetPasswordForEncryptHandler(signal chan os.Signal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		password := r.FormValue("password")

		if password != u.cfg.SecretKey.DecryptKey {
			signal <- syscall.SIGINT
		}

		err := u.encrypt.DecryptFile()
		if err != nil {
			log.Printf("%v\n", err)
		}

		u.securityPasswordCheck["check"] = true
	}
}
