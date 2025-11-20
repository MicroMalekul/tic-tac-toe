package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var database *sql.DB

var jwtKey = os.Getenv("JWT_KEY")

func main() {
	var err error
	err = godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	connStr := fmt.Sprintf("host=localhost user=%s password=%s dbname=tttdata sslmode=disable", os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"))
	database, err = sql.Open("postgres", connStr)
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
	http.HandleFunc("/heartbeat", GetAccessTokenHeartbeat)
	http.HandleFunc("/logout", Logout)

	http.ListenAndServe(":8080", nil)
}

type Claims struct {
	User_id int    `json:"user_id"`
	Version int    `json:"user_version"`
	Type    string `json:"token_type"`
	jwt.RegisteredClaims
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	query := "SELECT id, password FROM users WHERE username=$1"
	var hash string
	var user_id int
	err = database.QueryRow(query, creds.Username).Scan(&user_id, &hash)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var version int
	query = "UPDATE users SET user_version = user_version + 1 WHERE id=$1 RETURNING user_version"
	err = database.QueryRow(query, user_id).Scan(&version)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	expirationTime := time.Now().Add(30 * 24 * time.Hour)
	newClaims := &Claims{
		User_id: user_id,
		Version: version,
		Type:    "Refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	tokenString, _ := newToken.SignedString([]byte(jwtKey))

	json.NewEncoder(w).Encode(map[string]string{"refresh_token": tokenString, "access_token": ""})
}

func GetAccessTokenHeartbeat(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	var refreshTokenString string
	fmt.Sscanf(header, "Bearer %s", &refreshTokenString)
	claims := &Claims{}
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, claims, func(token *jwt.Token) (any, error) { return []byte(jwtKey), nil })
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	query := "SELECT user_version FROM users WHERE id=$1"
	var version int
	err = database.QueryRow(query, claims.User_id).Scan(&version)
	if err != nil || !refreshToken.Valid || version != claims.Version || claims.Type != "Refresh" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(15 * time.Minute)
	newClaims := &Claims{
		User_id: claims.User_id,
		Version: claims.Version,
		Type:    "Access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	accessTokenString, _ := newToken.SignedString([]byte(jwtKey))

	json.NewEncoder(w).Encode(map[string]string{"access_token": accessTokenString})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	var refreshTokenString string
	fmt.Sscanf(header, "Bearer %s", &refreshTokenString)
	claims := &Claims{}
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, claims, func(token *jwt.Token) (interface{}, error) { return []byte(jwtKey), nil })
	if err != nil || !refreshToken.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	query := "SELECT user_version FROM users WHERE id=$1"
	var version int
	err = database.QueryRow(query, claims.User_id).Scan(&version)

	if (err != nil || !refreshToken.Valid) || version != claims.Version {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	query = "UPDATE users SET user_version = user_version + 1 WHERE id=$1"
	_, err = database.Exec(query, claims.User_id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
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

	query = "INSERT INTO users (username, password, wins, user_version) VALUES ($1, $2, 0, 1)"
	hash, _ := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	_, err = database.Exec(query, creds.Username, hash)
	if err != nil {
		log.Fatal(err)
		http.Error(w, "Register failed", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Register succesful"))
}
