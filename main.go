package main

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	"net/http"
	"strings"
)

type CustomJWTClaim struct {
	Id string `json:"id"`
	jwt.StandardClaims
}

var authors []Author = []Author{
	Author{
		Id:        "author-1",
		Firstname: "Keir",
		Lastname:  "Whitlock",
		Username:  "kwhitlock",
		Password:  "pass",
	},
	Author{
		Id:        "author-2",
		Firstname: "James",
		Lastname:  "White",
		Username:  "jwhite",
		Password:  "pass",
	},
}

var articles []Article = []Article{
	Article{
		Id:      "article-1",
		Author:  "author-1",
		Title:   "Blog Post 1",
		Content: "This is is a blog",
	},
}

var JWT_SECRET []byte = []byte("mVNPjwGw!8WylLYfcH7C50juj*Tu82F^jZSCJMh9@FYi4mLyJc")

func ValidateJWT(t string) (interface{}, error) {

	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method %v", token.Header["alg"])
		}
		return JWT_SECRET, nil

	})
	if err != nil {
		return nil, errors.New(`{ "message": "` + err.Error() + `" }`)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var tokenData CustomJWTClaim
		mapstructure.Decode(claims, &tokenData)
		return tokenData, nil
	} else {
		return nil, errors.New(`{"message": "token invalid"}`)
	}
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bearer token (JWT Token)
		authorisationHeader := r.Header.Get("authorization")
		if authorisationHeader != "" {
			bearerToken := strings.Split(authorisationHeader, " ")
			if len(bearerToken) == 2 {
				decoded, err := ValidateJWT(bearerToken[1])
				if err != nil {
					w.Header().Add("content-type", "application/json")
					w.WriteHeader(500)
					w.Write([]byte(`{"message": "` + err.Error() + `" }`))
					return
				}
				context.Set(r, "decoded", decoded)
				next(w, r)
			}
		} else {
			w.Header().Add("content-type", "application/json")
			w.WriteHeader(500)
			w.Write([]byte(`{"message": "auth header is required" }`))
			return
		}
	})
}

func RootEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	w.Write([]byte(`{ "message": "Hello, world!}`))
}

func main() {
	fmt.Println("Starting the application...")
	router := mux.NewRouter()
	router.HandleFunc("/", RootEndpoint).Methods("GET")

	router.HandleFunc("/register", AuthorCreate).Methods("POST")
	router.HandleFunc("/login", AuthorLogin).Methods("POST")

	router.HandleFunc("/authors", AuthorGetAll).Methods("GET")
	router.HandleFunc("/author/{id}", AuthorGet).Methods("GET")
	router.HandleFunc("/author/{id}", AuthorDelete).Methods("DELETE")
	router.HandleFunc("/author/{id}", AuthorUpdate).Methods("PUT")

	router.HandleFunc("/articles", ArticleGetAll).Methods("GET")
	router.HandleFunc("/article", ValidateMiddleware(ArticleCreate)).Methods("POST")
	router.HandleFunc("/article/{id}", ArticleGet).Methods("GET")
	router.HandleFunc("/article/{id}", ValidateMiddleware(ArticleDelete)).Methods("DELETE")
	router.HandleFunc("/article/{id}", ValidateMiddleware(ArticleUpdate)).Methods("PUT")

	http.ListenAndServe(":12345", router)
}
