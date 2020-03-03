package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type ProfileHandler struct {
	profileTable *ProfileTable
	taskTable    *TaskTable
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedHeaders := "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token"
		w.Header().Set("Content-Type", "*")
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

type Answer struct {
	Id    string `json:"id"`
	Login string `json:"login"`
}

func checkRegist(login string, password string) bool {
	if len(login) < 4 || len(password) < 4 {
		return false
	} // @todo add more check
	return true
}

func (api *ProfileHandler) Registration(w http.ResponseWriter, r *http.Request) {
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

	if !checkRegist(newRegistrationInput.Login, newRegistrationInput.Password) {
		http.Error(w, `{"id":"-400"}`, 400) // неверный ввод
		return
	}

	newUser := &Profile{
		login:    newRegistrationInput.Login,
		password: newRegistrationInput.Password, //@todo hash()
		email:    newRegistrationInput.Email,
	}

	id, err := api.profileTable.AddProfile(newUser)
	if err != nil {
		http.Error(w, `{"id":"-400"}`, 400) // пользоатель уже есть
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

func shaHash(bv []byte) string {
	hasher := sha1.New()
	hasher.Write(bv)
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return sha
}

func (api *ProfileHandler) SignIn(w http.ResponseWriter, r *http.Request) {
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

	println("TRY LOGIN:", signInTry.Email, signInTry.Password) //@todo hash password
	user, err := api.profileTable.SignIn(signInTry.Email, signInTry.Password)
	if err != nil {
		println("SIGN IN: err check (email password)")
		isOK = false
	}

	if !isOK {
		http.Error(w, `{"id":"-500"}`, 400)
		println("error set cookie")
		return
	}

	SID := RandStringRunes(32)

	api.profileTable.sessions[SID] = user.login

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    SID,
		Expires:  time.Now().Add(10 * time.Hour),
		HttpOnly: true,
	}
	println("SET:", cookie.Name, "=", cookie.Value)
	http.SetCookie(w, cookie)

	someSecret := "hello world=)"
	token := shaHash([]byte(cookie.Value + user.email + someSecret))

	api.profileTable.tokens[user.login] = token
	w.Header().Set("X-CSRF-Token", token)

	type AnswerLogin struct {
		Exist bool   `json:"status"` // not use yet
		Id    uint   `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
		Token string `json:"token"`
	}

	answerLogin := new(AnswerLogin)
	answerLogin.Login = user.login
	answerLogin.Email = user.email
	answerLogin.Id = user.id
	answerLogin.Exist = true
	answerLogin.Token = token
	jsonData, err := json.Marshal(answerLogin)
	if err != nil && !isOK {
		println("Err singIN marshal")
		isOK = false
	}
	if !isOK {
		http.Error(w, `{"id":"-500"}`, 400)
		return
	}
	_, errWrite := w.Write(jsonData)
	if errWrite != nil {
		println("Err write in Login")
	}
}

func (api *ProfileHandler) LogOut(w http.ResponseWriter, r *http.Request) {
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
	println("delete cookie")
}

func (api *ProfileHandler) isAuthorize(r *http.Request) (bool, string) {
	authorized := false
	var login string
	session, err := r.Cookie("session_id")
	if err == nil && session != nil {
		login, authorized = api.profileTable.sessions[session.Value]
	}
	return authorized, login
}

func (api *ProfileHandler) GetUserData(w http.ResponseWriter, r *http.Request) {
	if (*r).Method != "POST" {
		return
	}

	println("Кто-то запрашивает данные пользователя по куке")
	type UserDataAnswer struct {
		Id    uint   `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
		Token string `json:"token"`
	}

	authorized, userlogin := api.isAuthorize(r)
	if !authorized {
		http.Error(w, ``, 403)
		return
	}

	userAnswer := new(UserDataAnswer)
	user, userDataErr := api.profileTable.GetUserDataFromTableByLogin(userlogin)
	if userDataErr != nil {
		http.Error(w, ``, 403)
		return
	} else {
		userAnswer.Id = user.id
		userAnswer.Login = user.login
		userAnswer.Email = user.email
		userAnswer.Token = api.profileTable.tokens[user.login]
	}

	println("return user data::login:", userAnswer.Login)
	jsonData, err := json.Marshal(userAnswer)
	if err != nil {
		log.Println(err)
		http.Error(w, ``, 500)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (api *ProfileHandler) ChangeProfile(w http.ResponseWriter, r *http.Request) {
	if (*r).Method != "POST" {
		return
	}
	println("Кто-то меняет профиль")

	authorized, userlogin := api.isAuthorize(r)
	if !authorized {
		println("Неавторизированный пользователь пытается менять что-то")
		http.Error(w, ``, 403)
		return
	}

	type UserDataAnswer struct {
		Id    uint   `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}

	isOK := true
	body, errRead := ioutil.ReadAll(r.Body)
	if errRead != nil {
		println("SIGN IN: err Read user body")
		isOK = false
	}

	type ChangeInput struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}

	ChangeTry := new(ChangeInput)
	errUnmarshal := json.Unmarshal(body, ChangeTry)
	if errUnmarshal != nil {
		println("SIGN IN: err Unmarshal user body")
		isOK = false
	}

	println("GET USER TOKEN:", ChangeTry.Token)
	if api.profileTable.tokens[userlogin] != ChangeTry.Token {
		println("Неавторизированный пользователь пытается менять что-то (неверный токен)")
		http.Error(w, ``, 403)
		return
	}

	println("Изменить логин на", ChangeTry.Email)
	changedUser, errChange := api.profileTable.ChangeProfile(userlogin, ChangeTry.Password, ChangeTry.Email)
	if errChange != nil {
		println("Profile: Новая почта занята")
		http.Error(w, ``, 503) // новый email занят
		return
	}
	newUserAnswer := new(UserDataAnswer)
	newUserAnswer.Login = changedUser.login
	newUserAnswer.Email = changedUser.email
	newUserAnswer.Id = changedUser.id

	println("Изменили логин на", newUserAnswer.Login)
	jsonData, err := json.Marshal(newUserAnswer)
	if err != nil || !isOK {
		log.Println(err)
		http.Error(w, ``, 500)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func (api *ProfileHandler) saveFile(w http.ResponseWriter, file multipart.File, userLogin string) {
	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}
	err = ioutil.WriteFile("./avatars/"+userLogin+"ava.png", data, 0666) // user format
	if err != nil {
		fmt.Fprintf(w, "%v", err)
		return
	}

}

func (api *ProfileHandler) GetAvatarFromUser(w http.ResponseWriter, r *http.Request) {
	if (*r).Method != "POST" {
		return
	}
	println("Кто-то загружает аватар")

	authorized, userlogin := api.isAuthorize(r)
	if !authorized {
		http.Error(w, ``, 403)
		return
	}

	token := r.Header.Get("X-Csrf-Token") // bad token
	if token != api.profileTable.tokens[userlogin] {
		http.Error(w, ``, 403)
		return
	}

	println(api.profileTable.mapUser[userlogin].email, " загружает аватар")

	r.ParseMultipartForm(10000)
	fileAvatar, _, errFirmFile := r.FormFile("avatar")
	if errFirmFile != nil {
		println("ERROR:", errFirmFile.Error())
		http.Error(w, ``, 405)
		return
	}

	api.saveFile(w, fileAvatar, userlogin)
	defer fileAvatar.Close()

	println("END WRITE FILE!")

}

func (api *ProfileHandler) SendAvatarToUser(w http.ResponseWriter, r *http.Request) {
	if (*r).Method != "GET" {
		return
	}
	println("Кто-то скачивает свой аватар")
	defaultPath := "./avatars/defaultAva.png"

	authorized, userlogin := api.isAuthorize(r)
	if !authorized {
		http.Error(w, ``, 403)
		return
	}

	println(userlogin, " скачивает аватар")
	fileName := "./avatars/" + userlogin + "ava.png"
	println("FILE NAME:", fileName)

	fileAvatar, err := os.Open(fileName)
	defer fileAvatar.Close()
	if err != nil {
		fileAvatar, _ = os.Open(defaultPath)
		//w.WriteHeader(http.StatusNotFound)
		//return
	}
	defer fileAvatar.Close()

	FileHeader := make([]byte, 512)
	fileAvatar.Read(FileHeader)

	FileContentType := http.DetectContentType(FileHeader)

	FileStat, _ := fileAvatar.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)

	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", FileContentType)
	w.Header().Set("Content-Length", FileSize)

	fileAvatar.Seek(0, 0)
	io.Copy(w, fileAvatar)

	println("END SEND FILE!")

}

func (api *ProfileHandler) SendTasks(w http.ResponseWriter, r *http.Request) {

	if (*r).Method != "POST" {
		return
	}
	println("Кто-то хочет получить таски")

	authorized, _ := api.isAuthorize(r)
	if !authorized {
		println("Неавторизированный пользователь пытается загрузить таски")
		http.Error(w, ``, 403)
		return
	}

	isOK := true
	body, errRead := ioutil.ReadAll(r.Body)
	if errRead != nil {
		println("SIGN IN: err Read user body")
		isOK = false
	}

	type TaskRequestInput struct {
		Numberoftask int `json:"numberoftask"`
	}

	taskRequest := new(TaskRequestInput)
	errUnmarshal := json.Unmarshal(body, taskRequest)
	if errUnmarshal != nil {
		println("TASKS: err Unmarshal user body")
		http.Error(w, ``, 400)
		return
	}

	println("I need get:", taskRequest.Numberoftask)
	tasksFromTable, errGetTask := api.taskTable.GetTasks(taskRequest.Numberoftask)
	if errGetTask != nil {
		println("Не удалось получить таски")
		http.Error(w, ``, 500)
	}

	jsonTasks, err := json.Marshal(tasksFromTable)
	if err != nil {
		println("Err tasks marshal")
		isOK = false
	}
	if !isOK {
		http.Error(w, `{"id":"-500"}`, 500)
		return
	}

	_, errWrite := w.Write(jsonTasks)
	if errWrite != nil {
		println("Err write in Login")
	}

	println("SEND TASKS")

}

func (api *ProfileHandler) SendOneTask(w http.ResponseWriter, r *http.Request) {
	if (*r).Method != "POST" {
		return
	}
	println("Кто-то хочет получить конкретный такс")

	authorized, _ := api.isAuthorize(r)
	if !authorized {
		println("Неавторизированный пользователь пытается загрузить задание")
		http.Error(w, ``, 403)
		return
	}

	isOK := true
	body, errRead := ioutil.ReadAll(r.Body)
	if errRead != nil {
		println("SIGN IN: err Read user body")
		isOK = false
	}

	type TaskRequestInput struct {
		TaskId int `json:"taskId"`
	}

	taskRequest := new(TaskRequestInput)
	errUnmarshal := json.Unmarshal(body, taskRequest)
	if errUnmarshal != nil {
		println("one task err Unmarshal user body")
		http.Error(w, ``, 400)
		return
	}

	task, errGetOneTask := api.taskTable.GetOneTask(taskRequest.TaskId)
	if errGetOneTask != nil {
		http.Error(w, `not found task by id`, 400)
		return
	}

	jsonTask, err := json.Marshal(task)
	if err != nil {
		println("Err one task marshal")
		isOK = false
	}
	if !isOK {
		http.Error(w, `{"id":"-500"}`, 500)
		return
	}

	_, errWrite := w.Write(jsonTask)
	if errWrite != nil {
		println("Err write in Login")
	}

	println("SEND ONE TASK")
}

func main() {

	//@todo  Добавить риид онли мютексы на только чтение

	r := mux.NewRouter()

	api := &ProfileHandler{
		profileTable: NewProfileTable(),
		taskTable:    NewTaskTable(),
	}

	api.taskTable.SetSomeStartTask()

	// js api
	r.HandleFunc("/registration", api.Registration)
	r.HandleFunc("/signin", api.SignIn)
	r.HandleFunc("/logout", api.LogOut)
	r.HandleFunc("/getuser", api.GetUserData)
	r.HandleFunc("/changeprofile", api.ChangeProfile) // token ok

	r.HandleFunc("/sendAvatar", api.GetAvatarFromUser) // token ok
	r.HandleFunc("/getAvatar{*}", api.SendAvatarToUser)

	r.HandleFunc("/getTasks", api.SendTasks)
	r.HandleFunc("/getOneTask", api.SendOneTask)

	log.Println("start serving :8080")
	errListen := http.ListenAndServe(":8080", CORSMiddleware(r))
	if errListen != nil {
		log.Fatal("Error: Not Listen")
	}
}
