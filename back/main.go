package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var database *sql.DB

const jwtKey = "abObasN0w"

func main() {
	var err error
	const connStrU string = "host=localhost user=tttapp password=abob4ik- dbname=tttdata sslmode=disable"

	database, err = sql.Open("postgres", connStrU)
	if err != nil {
		log.Fatal(err)
		return
	}
	err = database.Ping()
	if err != nil {
		log.Fatal(err)
		return
	}
	defer database.Close()
	http.HandleFunc("/login", Login)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/heartbeat", Heartbeat)

	http.ListenAndServe(":8080", nil)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	query := "SELECT password FROM users WHERE username=$1"
	var hash string
	err = database.QueryRow(query, creds.Username).Scan(&hash)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	newClaims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	tokenString, _ := newToken.SignedString([]byte(jwtKey))

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func Heartbeat(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	var tokenString string
	fmt.Sscanf(header, "Bearer %s", &tokenString)
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) { return []byte(jwtKey), nil })

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	newClaims := &Claims{
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	tokenString, _ = newToken.SignedString([]byte(jwtKey))

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

}

func Register(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	var exists string
	query := "SELECT username FROM users WHERE username=$1"

	err = database.QueryRow(query, creds.Username).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	query = "INSERT INTO users (username, password, wins) VALUES ($1, $2, 0)"
	hash, _ := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	_, err = database.Exec(query, creds.Username, hash)
	if err != nil {
		http.Error(w, "Register failed", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Register succesful"))
}
