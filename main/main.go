package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
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
		http.Error(w, `{"id":"-400"}`, 400)   // пользоатель уже есть
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

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
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
	w.Header().Set("Content-Type", "application/json")
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
	_, userLogin, err := api.profileTable.SignIn(signInTry.Email, signInTry.Password)
	if err != nil {
		println("SIGN IN: err check (email password)")
		isOK = false
	}

	if !isOK {
		http.Error(w, `{"id":"-500"}`, 500)
		println("error set cookie")
		return
	}

	SID := RandStringRunes(32)

	api.profileTable.sessions[SID] = userLogin

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    SID,
		Expires:  time.Now().Add(10 * time.Hour),
		HttpOnly: true,
	}
	println("SET:", cookie.Name, "=", cookie.Value)
	http.SetCookie(w, cookie)

	type AnswerLogin struct {
		Login string `json:"login"`
	}

	answerLogin := new(AnswerLogin)
	answerLogin.Login = userLogin
	jsonData, err := json.Marshal(answerLogin)
	if err != nil && !isOK {
		println("Err singIN marshal")
		isOK = false
	}
	if !isOK {
		http.Error(w, `{"id":"-500"}`, 500)
		return
	}
	w.Write(jsonData)
}

func (api *ProfileHandler) LogOut(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if (*r).Method != "POST" {
		return
	}

	session, err := r.Cookie("session_id")
	if err == http.ErrNoCookie {
		http.Error(w, `no session`, 401)
		return
	}

	if _, ok := api.profileTable.sessions[session.Value]; !ok {
		http.Error(w, `no sess`, 401)
		return
	}

	delete(api.profileTable.sessions, session.Value)

	session.Expires = time.Now().AddDate(0, 0, -1) //@todo add err check
	http.SetCookie(w, session)
}

func (api *ProfileHandler) isAuthorize(r *http.Request) bool {
	authorized := false
	session, err := r.Cookie("session_id")
	if err == nil && session != nil {
		_, authorized = api.profileTable.sessions[session.Value]
	}
	return authorized
}

func (api *ProfileHandler) GetUserData(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if (*r).Method != "POST" {
		return
	}

	println("Запрос данных пользователя")
	type UserDataAnswer struct {
		Exist bool   `json:"status"`
		Id    uint   `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}

	type UserDataRequest struct {
		Login string `json:"login"`
	}

	authorized := api.isAuthorize(r)
	if !authorized {
		http.Error(w, ``, 403)
		return
	}

	isOK := true
	body, errRead := ioutil.ReadAll(r.Body)
	if errRead != nil {
		println("GetUserData IN: err Read user body")
		isOK = false
	}

	println("BODY GET DATA:", string(body))
	userRequested := new(UserDataRequest)
	errUnmarshal := json.Unmarshal(body, userRequested)
	if errUnmarshal != nil {
		println("profile: err Unmarshal user login")
		isOK = false
	}

	userAnswer := new(UserDataAnswer)
	user, userDataErr := api.profileTable.GetUserDataFromTable(userRequested.Login)
	if userDataErr != nil {
		userAnswer.Exist = false
	} else {
		userAnswer.Exist = true
		userAnswer.Id = user.id
		userAnswer.Login = user.login
		userAnswer.Email = user.email
	}
	println("return user data::login:", userAnswer.Login)
	jsonData, err := json.Marshal(userAnswer)
	if err != nil && !isOK {
		log.Println(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
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
	r.HandleFunc("/getuser", api.GetUserData)

	log.Println("start serving :8080")
	errListen := http.ListenAndServe(":8080", r)
	if errListen != nil {
		log.Fatal("Error: Not Listen")
	}
}
