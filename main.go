package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux" // Router
	"github.com/joho/godotenv"
	_ "github.com/lib/pq" // PostgreSQL driver
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	host   = "localhost"
	port   = 5432
	dbname = "shop"
)

var db *sql.DB

// CartItem - структура товара в корзине
type CartItem struct {
	ID        int     `json:"id"`
	ProductID int     `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Price     float64 `json:"price"`
}

// OrderItem - структура товара в заказе
type OrderItem struct {
	ProductID int     `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Price     float64 `json:"price"`
}

// Product - структура товара
type Product struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	Quantity    int     `json:"quantity"`
	OwnerID     int     `json:"owner_id"`
}

// User - структура пользователя
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // admin, seller или buyer
}

// Claims - структура для хранения данных JWT-токена
type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// init is invoked before main()
func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

// Инициализация подключения к БД
func initDB() {
	user, _ := os.LookupEnv("DB_USERNAME")
	password, _ := os.LookupEnv("DB_PASSWORD")
	psqlInfo := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname,
	)
	var err error
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Unable to connect to the database:", err)
	}
	fmt.Println("Successfully connected to the database")
}

// Регистрация пользователя
func registerUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := `INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`
	_, err := db.Exec(query, user.Username, user.Password, user.Role)
	if err != nil {
		http.Error(w, "Unable to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// Вход пользователя и выдача токена
func loginUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var dbUser User
	query := `SELECT id, username, password, role FROM users WHERE username=$1`
	err := db.QueryRow(query, user.Username).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Password, &dbUser.Role)
	if err != nil || dbUser.Password != user.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := createToken(dbUser.ID, dbUser.Username, dbUser.Role)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Создание JWT токена
func createToken(userID int, username, role string) string {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret, _ := os.LookupEnv("JWT_SECRET")
	tokenString, _ := token.SignedString([]byte(jwtSecret))
	return tokenString
}

// Проверка, что пользователь - владелец товара или администратор
func isOwnerOrAdmin(userID int, role string, productID int) bool {
	if role == "admin" {
		return true
	}

	var ownerID int
	query := `SELECT owner_id FROM products WHERE id=$1`
	err := db.QueryRow(query, productID).Scan(&ownerID)
	if err != nil {
		return false
	}

	return ownerID == userID
}

// Middleware для проверки токена и ролей
func authenticate(role string, next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		jwtSecret, _ := os.LookupEnv("JWT_SECRET")
		if tokenString == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if role != "" && claims.Role != role {
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "claims", claims))
		next.ServeHTTP(w, r)
	})
}

// Создание нового товара (только для seller)
func createProduct(w http.ResponseWriter, r *http.Request) {
	var p Product
	claims := r.Context().Value("claims").(*Claims)
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	p.OwnerID = claims.UserID

	query := `INSERT INTO products (name, description, price, quantity, owner_id) 
              VALUES ($1, $2, $3, $4, $5) RETURNING id`
	err := db.QueryRow(query, p.Name, p.Description, p.Price, p.Quantity, p.OwnerID).Scan(&p.ID)
	if err != nil {
		http.Error(w, "Unable to create product", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(p)
}

// Получение всех товаров
func getProducts(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, description, price, quantity FROM products")
	if err != nil {
		http.Error(w, "Unable to fetch products", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Quantity); err != nil {
			http.Error(w, "Error scanning products", http.StatusInternalServerError)
			return
		}
		products = append(products, p)
	}

	json.NewEncoder(w).Encode(products)
}

// Получение товара по ID
func getProduct(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var p Product
	query := `SELECT id, name, description, price, quantity FROM products WHERE id=$1`
	err = db.QueryRow(query, id).Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Quantity)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Unable to fetch product", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(p)
}

// Обновление товара (доступно продавцу для своих товаров или администратору для любых)
func updateProduct(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	productID, _ := strconv.Atoi(mux.Vars(r)["id"])

	// Проверка, что товар принадлежит продавцу или у пользователя роль администратора
	if !isOwnerOrAdmin(claims.UserID, claims.Role, productID) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	var p Product
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := `UPDATE products SET name=$1, description=$2, price=$3, quantity=$4 WHERE id=$5`
	_, err := db.Exec(query, p.Name, p.Description, p.Price, p.Quantity, productID)
	if err != nil {
		http.Error(w, "Unable to update product", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Удаление товара (доступно продавцу для своих товаров или администратору для любых)
func deleteProduct(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	productID, _ := strconv.Atoi(mux.Vars(r)["id"])

	// Проверка, что товар принадлежит продавцу или у пользователя роль администратора
	if !isOwnerOrAdmin(claims.UserID, claims.Role, productID) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	query := `DELETE FROM products WHERE id=$1`
	_, err := db.Exec(query, productID)
	if err != nil {
		http.Error(w, "Unable to delete product", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Добавление товара в корзину
func addToCart(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.UserID

	var item CartItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var currentQuantity int
	query := `SELECT quantity FROM cart_items WHERE user_id=$1 AND product_id=$2`
	err := db.QueryRow(query, userID, item.ProductID).Scan(&currentQuantity)
	if err == sql.ErrNoRows {
		query = `INSERT INTO cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3)`
		_, err = db.Exec(query, userID, item.ProductID, item.Quantity)
	} else {
		query = `UPDATE cart_items SET quantity=$1 WHERE user_id=$2 AND product_id=$3`
		_, err = db.Exec(query, currentQuantity+item.Quantity, userID, item.ProductID)
	}
	if err != nil {
		http.Error(w, "Unable to add item to cart", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Получение товаров из корзины
func getCart(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.UserID

	query := `SELECT cart_items.id, product_id, quantity, price FROM cart_items 
              JOIN products ON cart_items.product_id = products.id WHERE user_id=$1`
	rows, err := db.Query(query, userID)
	if err != nil {
		http.Error(w, "Unable to retrieve cart", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cart []CartItem
	for rows.Next() {
		var item CartItem
		if err := rows.Scan(&item.ID, &item.ProductID, &item.Quantity, &item.Price); err != nil {
			http.Error(w, "Error scanning cart items", http.StatusInternalServerError)
			return
		}
		cart = append(cart, item)
	}
	json.NewEncoder(w).Encode(cart)
}

// Изменение количества товара в корзине
func updateCartItem(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.UserID
	productID := mux.Vars(r)["id"]

	var item CartItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := `UPDATE cart_items SET quantity=$1 WHERE user_id=$2 AND product_id=$3`
	_, err := db.Exec(query, item.Quantity, userID, productID)
	if err != nil {
		http.Error(w, "Unable to update cart item", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Удаление товара из корзины
func deleteCartItem(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.UserID
	productID := mux.Vars(r)["id"]

	query := `DELETE FROM cart_items WHERE user_id=$1 AND product_id=$2`
	_, err := db.Exec(query, userID, productID)
	if err != nil {
		http.Error(w, "Unable to delete cart item", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Оформление заказа
func checkout(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.UserID

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Unable to start transaction", http.StatusInternalServerError)
		return
	}

	// Получаем товары из корзины и вычисляем общую стоимость
	var totalAmount float64
	query := `SELECT product_id, quantity, price FROM cart_items 
              JOIN products ON cart_items.product_id = products.id WHERE user_id=$1`
	rows, err := tx.Query(query, userID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Unable to retrieve cart items", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []OrderItem
	for rows.Next() {
		var item OrderItem
		if err := rows.Scan(&item.ProductID, &item.Quantity, &item.Price); err != nil {
			tx.Rollback()
			http.Error(w, "Error reading cart items", http.StatusInternalServerError)
			return
		}
		items = append(items, item)
		totalAmount += item.Price * float64(item.Quantity)
	}

	// Создаем заказ
	query = `INSERT INTO orders (user_id, total_amount) VALUES ($1, $2) RETURNING id`
	var orderID int
	err = tx.QueryRow(query, userID, totalAmount).Scan(&orderID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Unable to create order", http.StatusInternalServerError)
		return
	}

	// Добавляем товары из корзины в заказ
	for _, item := range items {
		query = `INSERT INTO order_items (order_id, product_id, quantity, price) VALUES ($1, $2, $3, $4)`
		_, err = tx.Exec(query, orderID, item.ProductID, item.Quantity, item.Price)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Unable to add order items", http.StatusInternalServerError)
			return
		}
	}

	// Очищаем корзину
	query = `DELETE FROM cart_items WHERE user_id=$1`
	_, err = tx.Exec(query, userID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Unable to clear cart", http.StatusInternalServerError)
		return
	}

	tx.Commit()
	json.NewEncoder(w).Encode(map[string]interface{}{"order_id": orderID, "total_amount": totalAmount})
}

func main() {
	initDB()

	router := mux.NewRouter()

	// Маршруты аутентификации
	router.HandleFunc("/register", registerUser).Methods("POST")
	router.HandleFunc("/login", loginUser).Methods("POST")

	// Маршруты для работы с продуктами
	router.HandleFunc("/products", authenticate("seller", createProduct)).Methods("POST")       // Только продавец
	router.HandleFunc("/products", authenticate("", getProducts)).Methods("GET")                // Все роли
	router.HandleFunc("/products/{id}", authenticate("", getProduct)).Methods("GET")            // Все роли
	router.HandleFunc("/products/{id}", authenticate("seller", updateProduct)).Methods("PUT")   // Продавец или администратор
	router.HandleFunc("/products/{id}", authenticate("admin", deleteProduct)).Methods("DELETE") // Продавец или администратор

	// Маршруты корзины
	router.HandleFunc("/cart", authenticate("buyer", addToCart)).Methods("POST")             // Добавление товара в корзину
	router.HandleFunc("/cart", authenticate("buyer", getCart)).Methods("GET")                // Получение товаров из корзины
	router.HandleFunc("/cart/{id}", authenticate("buyer", updateCartItem)).Methods("PUT")    // Изменение количества
	router.HandleFunc("/cart/{id}", authenticate("buyer", deleteCartItem)).Methods("DELETE") // Удаление товара
	router.HandleFunc("/checkout", authenticate("buyer", checkout)).Methods("POST")          // Оформление заказа

	fmt.Println("Server is running on port 8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}
