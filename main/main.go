package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type ProfileHandler struct {
	profileTable *ProfileTable
}

func enableCors(w *http.ResponseWriter) {
	allowedHeaders := "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization"
	(*w).Header().Set("Content-Type", "*")
	(*w).Header().Set("Access-Control-Allow-Headers", allowedHeaders)
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
}

type Answer struct {
	Id    string `json:"id"`
	Login string `json:"login"`
}

func (api *ProfileHandler) Registration(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)
	if (*r).Method != "POST" {
		return
	}
	println("Кто-то пытается зарегистрироваться")

	isOK := true

	body, errRead := ioutil.ReadAll(r.Body)
	if errRead != nil {
		println("REGISTRATION: err Read user body")
		isOK = false
	}

	type RegistrationInput struct {
		Login    string `json:"login"`
		Password string `json:"Password"`
		Email    string `json:"email"`
	}

	newRegistrationInput := new(RegistrationInput)
	errUnmarshal := json.Unmarshal(body, newRegistrationInput)
	if errUnmarshal != nil {
		println("REGISTRATION: err Unmarshal user body")
		isOK = false
	}

	newUser := &Profile{
		login:    newRegistrationInput.Login,
		password: newRegistrationInput.Password,
		email:    newRegistrationInput.Email,
	}

	id, err := api.profileTable.AddProfile(newUser)
	if err != nil {
		http.Error(w, `{"id":"-500"}`, 500)
		// если пользователь уже есть то это уж не ошибка сервера
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if !isOK {
		BadAnswer := Answer{
			Id:    strconv.Itoa(int(id)),
			Login: newUser.login,
		}
		BadJsonData, err := json.Marshal(BadAnswer)
		if err != nil {
			log.Println(err)
			http.Error(w, `{"id":"-500"}`, 500)
		}
		w.Write(BadJsonData)
		return
	}

	answer := Answer{
		Id:    strconv.Itoa(int(id)),
		Login: newUser.login,
	}

	jsonData, err := json.Marshal(answer)
	if err != nil {
		log.Println(err)
	}
	w.Write(jsonData)
}

func addCookie(w *http.ResponseWriter, name string, value string) {
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:    name,
		Value:   value,
		Expires: expire,
	}
	http.SetCookie(*w, &cookie)
}

func (api *ProfileHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if (*r).Method != "POST" {
		return
	}
	println("Кто-то пытается зайти в систему")

	isOK := true

	body, errRead := ioutil.ReadAll(r.Body)
	if errRead != nil {
		println("SIGN IN: err Read user body")
		isOK = false
	}

	type SignInInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	signInTry := new(SignInInput)
	errUnmarshal := json.Unmarshal(body, signInTry)
	if errUnmarshal != nil {
		println("SIGN IN: err Unmarshal user body")
		isOK = false
	}

	println("TRY LOGIN:", signInTry.Email, signInTry.Password)
	userId, userLogin, err := api.profileTable.SignIn(signInTry.Email, signInTry.Password)
	if err != nil {
		println("SIGN IN: err check (email password)")
		isOK = false
	}

	w.Header().Set("Content-Type", "application/json")
	if !isOK {
		http.Error(w, `{"id":"-500"}`, 500)
		return
	}

	//@todo сессия
	addCookie(&w, "TestCookieName", "TestValue")

	answer := Answer{
		Id:    strconv.Itoa(int(userId)),
		Login: userLogin,
	}
	jsonData, err := json.Marshal(answer)
	if err != nil {
		log.Println(err)
	}
	w.Write(jsonData)
}

func (api *ProfileHandler) LogOut(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if (*r).Method != "POST" {
		return
	}
	println("Кто-то пытается выйти из матрицы")

}

func (api *ProfileHandler) HelloGo(w http.ResponseWriter, r *http.Request) {
	method := r.Method
	fmt.Fprintln(w, method, r.URL.String(), "hello")
}

/* Использовалось чтобы отдавать статику пока нет nginx
func (api *ProfileHandler) GetMainPage(w http.ResponseWriter, r *http.Request) {
	w.Write(mainPage)
}

func (api *ProfileHandler) GetMainCss(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Write(mainCss)
}

func (api *ProfileHandler) GetMainJs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	w.Write(mainJs)
}

func (api *ProfileHandler) GetMainAjaxJs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	w.Write(mainAjax)
}

var mainPage []byte
var mainCss []byte
var mainJs []byte
var mainAjax []byte

func readMainPages() {
	// mian page
	var mainPagePath = "../public/index.html"
	file, err := os.Open(mainPagePath)
	if err != nil {
		log.Fatal("Error: Not valid file name")
	}
	defer file.Close()
	mainPage, err = ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("Error: Read error")
	}

	// main css
	var mainPageCssPath = "../public/main.css"
	fileCss, err := os.Open(mainPageCssPath)
	if err != nil {
		log.Fatal("Error: Not valid file name")
	}
	defer fileCss.Close()
	mainCss, err = ioutil.ReadAll(fileCss)
	if err != nil {
		log.Fatal("Error: Read error")
	}

	// main js
	var mainPageJsPath = "../public/main.js"
	fileJs, err := os.Open(mainPageJsPath)
	if err != nil {
		log.Fatal("Error: Not valid file name")
	}
	defer fileJs.Close()
	mainJs, err = ioutil.ReadAll(fileJs)
	if err != nil {
		log.Fatal("Error: Read error")
	}

	// main js
	var mainPageAjaxPath = "../public/modules/ajax.js"
	fileJsAjax, err := os.Open(mainPageAjaxPath)
	if err != nil {
		log.Fatal("Error: Not valid file name")
	}
	defer fileJs.Close()
	mainAjax, err = ioutil.ReadAll(fileJsAjax)
	if err != nil {
		log.Fatal("Error: Read error")
	}
}
*/

func main() {

	// before server starts, читаем 1 раз, помним всегда
	//readMainPages() // возможна паника но узнаем сразу до старта сервера

	r := mux.NewRouter()

	api := &ProfileHandler{
		profileTable: NewProfileTable(),
	}

	/* пока нет nginx статику отдаем сами
	r.HandleFunc("/", api.GetMainPage)
	r.HandleFunc("/index{*}", api.GetMainPage)

	r.HandleFunc("/main.css", api.GetMainCss)
	r.HandleFunc("/main.js", api.GetMainJs)
	r.HandleFunc("/modules/ajax.js", api.GetMainAjaxJs)
	*/

	// js api
	r.HandleFunc("/registration", api.Registration)
	r.HandleFunc("/signin", api.SignIn)
	r.HandleFunc("/logout", api.LogOut)

	log.Println("start serving :8080")
	errListen := http.ListenAndServe(":8080", r)
	if errListen != nil {
		log.Fatal("Error: Not Listen")
	}
}
