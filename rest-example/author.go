package main

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
	"net/http"
	"time"
)

type Author struct {
	Id        string `json:"id,omitempty" validate:"omitifempty,uuid"`
	Firstname string `json:"firstname,omitempty" validate:"required"`
	Lastname  string `json:"lastname,omitempty" validate:"required"`
	Username  string `json:"username,omitempty" validate:"required"`
	Password  string `json:"password,omitempty" validate:"required,gte=4"`
}

func AuthorCreate(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")
	var author Author
	json.NewDecoder(r.Body).Decode(&author)

	validate := validator.New() // initialise the validator
	err := validate.Struct(author)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(author.Password), 10)

	author.Id = uuid.Must(uuid.NewV4(), nil).String()
	author.Password = string(hash)
	authors = append(authors, author)

	json.NewEncoder(w).Encode(authors)

}

func AuthorLogin(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")
	var data Author
	json.NewDecoder(r.Body).Decode(&data)

	validate := validator.New() // initialise the validator
	err := validate.StructExcept(data, "Firstname", "Lastname")
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	for _, author := range authors {
		if author.Username == data.Username {
			err := bcrypt.CompareHashAndPassword([]byte(author.Password), []byte(data.Password))
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(`{ "message": "invalid password" }`))
				return
			}
			claims := CustomJWTClaim{
				Id: author.Id,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Local().Add(time.Hour).Unix(),
					Issuer:    "The Polyglot Developer",
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, _ := token.SignedString(JWT_SECRET)

			w.Write([]byte(`{ "token": "` + tokenString + `" }`))
			return
		}
	}

	w.Write([]byte(`{ "message": "invalid username" }`))
}

func AuthorGetAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	json.NewEncoder(w).Encode(authors)
}

func AuthorGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")

	params := mux.Vars(r) // http://localhost/get/12345

	for _, author := range authors {
		if author.Id == params["id"] {
			json.NewEncoder(w).Encode(author)
			return
		}
	}
	json.NewEncoder(w).Encode(Author{})
}

func AuthorDelete(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")

	params := mux.Vars(r) // http://localhost/get/12345

	// using a loop as not using a database yet
	for index, author := range authors {
		if author.Id == params["id"] {
			authors := append(authors[:index], authors[index+1:]...)
			json.NewEncoder(w).Encode(authors)
			return
		}
	}

	json.NewEncoder(w).Encode(Author{})
}

func AuthorUpdate(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")
	params := mux.Vars(r) // http://localhost/get/12345

	var changes Author
	json.NewDecoder(r.Body).Decode(&changes)

	validate := validator.New() // initialise the validator
	err := validate.StructExcept(changes, "Firstname", "Lastname", "Username", "Password")
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	for index, author := range authors {
		if author.Id == params["id"] {
			if changes.Firstname != "" {
				author.Firstname = changes.Firstname
			}
			if changes.Lastname != "" {
				author.Lastname = changes.Lastname
			}
			if changes.Username != "" {
				author.Username = changes.Username
			}
			if changes.Password != "" {
				err = validate.Var(changes.Password, "gte=4")

				if err != nil {
					w.WriteHeader(500)
					w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
					return
				}

				hash, _ := bcrypt.GenerateFromPassword([]byte(changes.Password), 10)
				author.Password = string(hash)
			}

			authors[index] = author
			json.NewEncoder(w).Encode(authors)
			return
		}
	}
	json.NewEncoder(w).Encode(Author{})
}
