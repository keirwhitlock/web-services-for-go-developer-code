package main

import (
	"encoding/json"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
	"gopkg.in/go-playground/validator.v9"
	"net/http"
)

type Article struct {
	Id      string `json:"id,omitempty" validate:"omitempty,uuid"`
	Author  string `json:"author,omitempty" validate:"isdefault"`
	Title   string `json:"title,omitempty" validate:"required"`
	Content string `json:"content,omitempty" validate:"required"`
}

func ArticleGetAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	json.NewEncoder(w).Encode(articles)
}

func ArticleGet(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")

	params := mux.Vars(r)

	for _, article := range articles {
		if article.Id == params["id"] {
			json.NewEncoder(w).Encode(article)
			return
		}
	}
	json.NewEncoder(w).Encode(Article{})
}

func ArticleCreate(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")
	var article Article
	json.NewDecoder(r.Body).Decode(&article)

	/*
		tokenString := r.URL.Query().Get("token")

		token, err := ValidateJWT(tokenString)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
			return
		}
	*/
	token := context.Get(r, "decoded").(CustomJWTClaim)
	validate := validator.New()
	err := validate.Struct(article)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}

	article.Id = uuid.Must(uuid.NewV4(), nil).String()
	article.Author = token.Id
	articles = append(articles, article)

	json.NewEncoder(w).Encode(articles)
}

func ArticleDelete(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")

	params := mux.Vars(r)

	token := context.Get(r, "decoded").(CustomJWTClaim)

	for index, article := range articles {
		if article.Id == params["id"] && article.Author == token.Id { // the && article.Author == token.Id, checks the article owner can only delete an article.
			articles = append(articles[:index], articles[index+1:]...)
			json.NewEncoder(w).Encode(articles)
			return
		}
	}
	json.NewEncoder(w).Encode(Article{})
}

func ArticleUpdate(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")

	params := mux.Vars(r)
	var changes Article
	json.NewDecoder(r.Body).Decode(&changes)

	token := context.Get(r, "decoded").(CustomJWTClaim)

	for index, article := range articles {
		if article.Id == params["id"] && article.Author == token.Id {
			if changes.Title != "" {
				article.Title = changes.Title
			}

			if changes.Content != "" {
				article.Content = changes.Content
			}

			articles[index] = article
			json.NewEncoder(w).Encode(articles)
			return
		}
	}
	json.NewEncoder(w).Encode(Article{})
}
