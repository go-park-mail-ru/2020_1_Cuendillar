package main

import (
	"errors"
	"log"
	"sync"
)

type Profile struct {
	id       uint
	email    string
	login    string
	password string
}

type ProfileTable struct {
	mapUser      map[string]*Profile
	mapUserEmail map[string]*Profile
	sessions     map[string]string // [token]login
	mu           sync.RWMutex
	nextID       uint
}

func NewProfileTable() *ProfileTable {
	return &ProfileTable{
		mu:           sync.RWMutex{},
		mapUser:      make(map[string]*Profile), // fast login
		mapUserEmail: make(map[string]*Profile), // fast email
		sessions:     make(map[string]string),
	}
}

func showUsers(profTable *ProfileTable) {
	for _, user := range profTable.mapUser {
		println("id:", user.id, "   login:", user.login, "   password:", user.password,
			"   email:", user.email)
	}
}

func (profTable *ProfileTable) AddProfile(newUser *Profile) (uint, error) {
	log.Println("Add PROFILE called")

	_, exist := profTable.mapUser[newUser.login]
	if exist == true {
		return 0, errors.New("login already exist")
	}

	profTable.mu.Lock()
	profTable.nextID++
	newUser.id = profTable.nextID
	log.Println("nextID", profTable.nextID)
	profTable.mapUser[newUser.login] = newUser
	profTable.mapUserEmail[newUser.email] = newUser
	profTable.mu.Unlock()

	println("After add new User. Users:")
	showUsers(profTable)
	println("===================")

	return newUser.id, nil
}

func (profTable *ProfileTable) SignIn(email string, password string) (uint, string, error) {
	user, exist := profTable.mapUserEmail[email]
	if exist != true {
		return 0, "", errors.New("don't have that user")
	}
	if user.password == password {
		return user.id, user.login, nil
	}
	return 0, "", errors.New("wrong password")
}

func (profTable *ProfileTable) GetUserDataFromTable(login string) (*Profile, error) {
	user, exist := profTable.mapUser[login]
	if exist != true {
		return nil, errors.New("not have this user")
	}
	return user, nil
}
