package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	db        *sql.DB
	templates *template.Template
	sessions  map[string]Session
	mu        sync.Mutex
}

type Session struct {
	userID  int
	expires time.Time
}

func main() {
	db, err := sql.Open("sqlite3", "forum.db")
	if err != nil {
		log.Fatal(err)
	}
	if err := initDB(db); err != nil {
		log.Fatal(err)
	}

	tpl := template.Must(template.ParseGlob(path.Join("templates", "*.html")))
	s := &Server{db: db, templates: tpl, sessions: make(map[string]Session)}

    // Use a single route handler to centralise path handling. This allows us
    // to return custom error pages for unknown routes rather than the default
    // plain text 404. Static files are still served via the route function.
    http.HandleFunc("/", s.route)
    log.Println("Listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func initDB(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );`,
		`CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );`,
		`CREATE TABLE IF NOT EXISTS post_categories (
            post_id INTEGER,
            category_id INTEGER,
            PRIMARY KEY (post_id, category_id)
        );`,
		`CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );`,
		`CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_type TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            value INTEGER NOT NULL,
            UNIQUE(user_id, target_type, target_id)
        );`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM categories").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		for _, c := range []string{"General", "Announcements", "Random"} {
			if _, err := db.Exec("INSERT INTO categories(name) VALUES(?)", c); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) currentUser(r *http.Request) (int, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie.Value]
	if !ok || sess.expires.Before(time.Now()) {
		return 0, false
	}
	return sess.userID, true
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	userID, _ := s.currentUser(r)
	query := `SELECT p.id, p.title, p.content, u.username, p.created_at,
        IFNULL(SUM(CASE WHEN l.value=1 THEN 1 END),0) AS likes,
        IFNULL(SUM(CASE WHEN l.value=-1 THEN 1 END),0) AS dislikes
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN likes l ON l.target_type='post' AND l.target_id=p.id`
	args := []interface{}{}
	if cat := r.URL.Query().Get("category"); cat != "" {
		query += ` JOIN post_categories pc ON pc.post_id=p.id JOIN categories c ON c.id=pc.category_id WHERE c.name=?`
		args = append(args, cat)
	}
	query += " GROUP BY p.id ORDER BY p.created_at DESC"
    rows, err := s.db.Query(query, args...)
    if err != nil {
        s.renderError(w, http.StatusInternalServerError)
        return
    }
	defer rows.Close()
	type Post struct {
		ID       int
		Title    string
		Content  string
		Author   string
		Created  time.Time
		Likes    int
		Dislikes int
	}
	var posts []Post
	for rows.Next() {
		var p Post
        if err := rows.Scan(&p.ID, &p.Title, &p.Content, &p.Author, &p.Created, &p.Likes, &p.Dislikes); err != nil {
            s.renderError(w, http.StatusInternalServerError)
            return
        }
		posts = append(posts, p)
	}
    catsRows, _ := s.db.Query("SELECT name FROM categories")
    defer catsRows.Close()
    var cats []string
    for catsRows.Next() {
        var name string
        catsRows.Scan(&name)
        cats = append(cats, name)
    }
    data := struct {
        Posts      []Post
        Categories []string
        UserID     int
    }{posts, cats, userID}
    if err := s.templates.ExecuteTemplate(w, "index.html", data); err != nil {
        s.renderError(w, http.StatusInternalServerError)
    }
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        // Render the registration page with a zero UserID to show login/register links
        data := struct{ UserID int }{0}
        if err := s.templates.ExecuteTemplate(w, "register.html", data); err != nil {
            s.renderError(w, http.StatusInternalServerError)
        }
    case http.MethodPost:
        email := r.FormValue("email")
        username := r.FormValue("username")
        password := r.FormValue("password")
        if email == "" || username == "" || password == "" {
            s.renderError(w, http.StatusBadRequest)
            return
        }
        hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            s.renderError(w, http.StatusInternalServerError)
            return
        }
        _, err = s.db.Exec("INSERT INTO users(email, username, password) VALUES(?,?,?)", email, username, string(hashed))
        if err != nil {
            s.renderError(w, http.StatusBadRequest)
            return
        }
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    default:
        s.renderError(w, http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        // Show login page with zero UserID
        data := struct{ UserID int }{0}
        if err := s.templates.ExecuteTemplate(w, "login.html", data); err != nil {
            s.renderError(w, http.StatusInternalServerError)
        }
    case http.MethodPost:
        email := r.FormValue("email")
        password := r.FormValue("password")
        var id int
        var hashed string
        err := s.db.QueryRow("SELECT id, password FROM users WHERE email=?", email).Scan(&id, &hashed)
        if err != nil {
            s.renderError(w, http.StatusBadRequest)
            return
        }
        if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) != nil {
            s.renderError(w, http.StatusBadRequest)
            return
        }
        token := uuid.New().String()
        s.mu.Lock()
        s.sessions[token] = Session{userID: id, expires: time.Now().Add(24 * time.Hour)}
        s.mu.Unlock()
        http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", Expires: time.Now().Add(24 * time.Hour)})
        http.Redirect(w, r, "/", http.StatusSeeOther)
    default:
        s.renderError(w, http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		cookie.Expires = time.Unix(0, 0)
		http.SetCookie(w, cookie)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/post/")
	parts := strings.Split(rest, "/")
	if len(parts) > 0 && parts[0] == "create" {
		s.handleCreatePost(w, r)
		return
	}
    id, err := strconv.Atoi(parts[0])
    if err != nil {
        s.renderError(w, http.StatusNotFound)
        return
    }
	if len(parts) > 1 {
		action := parts[1]
		switch action {
		case "comment":
			s.handleAddComment(w, r, id)
			return
		case "like":
			s.handleLike(w, r, "post", id, true)
			return
		case "dislike":
			s.handleLike(w, r, "post", id, false)
			return
		}
	}
	s.showPost(w, r, id)
}

func (s *Server) showPost(w http.ResponseWriter, r *http.Request, id int) {
	userID, _ := s.currentUser(r)
	query := `SELECT p.title, p.content, u.username, p.created_at,
        IFNULL(SUM(CASE WHEN l.value=1 THEN 1 END),0) AS likes,
        IFNULL(SUM(CASE WHEN l.value=-1 THEN 1 END),0) AS dislikes
        FROM posts p
        JOIN users u ON p.user_id=u.id
        LEFT JOIN likes l ON l.target_type='post' AND l.target_id=p.id
        WHERE p.id=? GROUP BY p.id`
	var post struct {
		Title    string
		Content  string
		Author   string
		Created  time.Time
		Likes    int
		Dislikes int
	}
    if err := s.db.QueryRow(query, id).Scan(&post.Title, &post.Content, &post.Author, &post.Created, &post.Likes, &post.Dislikes); err != nil {
        s.renderError(w, http.StatusNotFound)
        return
    }
    rows, err := s.db.Query(`SELECT c.id, c.content, u.username,
        IFNULL(SUM(CASE WHEN l.value=1 THEN 1 END),0) AS likes,
        IFNULL(SUM(CASE WHEN l.value=-1 THEN 1 END),0) AS dislikes
        FROM comments c
        JOIN users u ON c.user_id=u.id
        LEFT JOIN likes l ON l.target_type='comment' AND l.target_id=c.id
        WHERE c.post_id=? GROUP BY c.id ORDER BY c.created_at`, id)
    if err != nil {
        s.renderError(w, http.StatusInternalServerError)
        return
    }
	defer rows.Close()
	type Comment struct {
		ID       int
		Content  string
		Author   string
		Likes    int
		Dislikes int
	}
	var comments []Comment
	for rows.Next() {
		var c Comment
        if err := rows.Scan(&c.ID, &c.Content, &c.Author, &c.Likes, &c.Dislikes); err != nil {
            s.renderError(w, http.StatusInternalServerError)
            return
        }
		comments = append(comments, c)
	}
    data := struct {
        ID       int
        Post     interface{}
        Comments []Comment
        UserID   int
    }{id, post, comments, userID}
    if err := s.templates.ExecuteTemplate(w, "post.html", data); err != nil {
        s.renderError(w, http.StatusInternalServerError)
    }
}

func (s *Server) handleCreatePost(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
    switch r.Method {
    case http.MethodGet:
        rows, _ := s.db.Query("SELECT id, name FROM categories")
        defer rows.Close()
        type Cat struct {
            ID   int
            Name string
        }
        var cats []Cat
        for rows.Next() {
            var c Cat
            rows.Scan(&c.ID, &c.Name)
            cats = append(cats, c)
        }
        data := struct {
            UserID int
            Cats   []Cat
        }{userID, cats}
        if err := s.templates.ExecuteTemplate(w, "create_post.html", data); err != nil {
            s.renderError(w, http.StatusInternalServerError)
        }
    case http.MethodPost:
        title := r.FormValue("title")
        content := r.FormValue("content")
        if title == "" || content == "" {
            s.renderError(w, http.StatusBadRequest)
            return
        }
        res, err := s.db.Exec("INSERT INTO posts(user_id, title, content) VALUES(?,?,?)", userID, title, content)
        if err != nil {
            s.renderError(w, http.StatusInternalServerError)
            return
        }
        postID, _ := res.LastInsertId()
        cats := r.Form["categories"]
        for _, c := range cats {
            s.db.Exec("INSERT INTO post_categories(post_id, category_id) VALUES(?,?)", postID, c)
        }
        http.Redirect(w, r, fmt.Sprintf("/post/%d", postID), http.StatusSeeOther)
    default:
        s.renderError(w, http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleAddComment(w http.ResponseWriter, r *http.Request, postID int) {
	userID, ok := s.currentUser(r)
    if !ok {
        s.renderError(w, http.StatusUnauthorized)
        return
    }
    if r.Method != http.MethodPost {
        s.renderError(w, http.StatusMethodNotAllowed)
        return
    }
    content := r.FormValue("content")
    if strings.TrimSpace(content) == "" {
        s.renderError(w, http.StatusBadRequest)
        return
    }
    if _, err := s.db.Exec("INSERT INTO comments(post_id, user_id, content) VALUES(?,?,?)", postID, userID, content); err != nil {
        s.renderError(w, http.StatusInternalServerError)
        return
    }
    http.Redirect(w, r, fmt.Sprintf("/post/%d", postID), http.StatusSeeOther)
}

// route is the central HTTP handler. It examines the request path and
// delegates to the appropriate handler. If no handler matches, a custom
// 404 page is rendered. Static assets are served through this method too.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
    // Serve static files (e.g. CSS) before anything else
    if strings.HasPrefix(r.URL.Path, "/static/") {
        http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP(w, r)
        return
    }
    switch {
    case r.URL.Path == "/" || r.URL.Path == "":
        s.handleIndex(w, r)
    case r.URL.Path == "/register":
        s.handleRegister(w, r)
    case r.URL.Path == "/login":
        s.handleLogin(w, r)
    case r.URL.Path == "/logout":
        s.handleLogout(w, r)
    case r.URL.Path == "/about":
        s.handleAbout(w, r)
    case strings.HasPrefix(r.URL.Path, "/post/"):
        s.handlePost(w, r)
    case strings.HasPrefix(r.URL.Path, "/comment/"):
        s.handleCommentLike(w, r)
    default:
        s.renderError(w, http.StatusNotFound)
    }
}

// handleAbout renders a static About page. It supplies the current user ID
// so that the navigation bar can reflect authentication state.
func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        s.renderError(w, http.StatusMethodNotAllowed)
        return
    }
    userID, _ := s.currentUser(r)
    data := struct {
        UserID int
    }{userID}
    if err := s.templates.ExecuteTemplate(w, "about.html", data); err != nil {
        s.renderError(w, http.StatusInternalServerError)
    }
}

// renderError writes a custom error page based on the status code. If a
// specific template does not exist, it falls back to the default HTTP
// status text. Supported templates include 400.html, 404.html and 500.html.
func (s *Server) renderError(w http.ResponseWriter, code int) {
    w.WriteHeader(code)
    tmpl := fmt.Sprintf("%d.html", code)
    err := s.templates.ExecuteTemplate(w, tmpl, nil)
    if err != nil {
        // If no custom template is found, fall back to the default text
        http.Error(w, http.StatusText(code), code)
    }
}

func (s *Server) handleLike(w http.ResponseWriter, r *http.Request, targetType string, targetID int, isLike bool) {
    userID, ok := s.currentUser(r)
    if !ok {
        s.renderError(w, http.StatusUnauthorized)
        return
    }
    if r.Method != http.MethodPost {
        s.renderError(w, http.StatusMethodNotAllowed)
        return
    }
	value := -1
	if isLike {
		value = 1
	}
	var current int
    err := s.db.QueryRow("SELECT value FROM likes WHERE user_id=? AND target_type=? AND target_id=?", userID, targetType, targetID).Scan(&current)
    if err != nil && !errors.Is(err, sql.ErrNoRows) {
        s.renderError(w, http.StatusInternalServerError)
        return
    }
	if current == value {
		s.db.Exec("DELETE FROM likes WHERE user_id=? AND target_type=? AND target_id=?", userID, targetType, targetID)
	} else if current == -value {
		s.db.Exec("UPDATE likes SET value=? WHERE user_id=? AND target_type=? AND target_id=?", value, userID, targetType, targetID)
	} else {
        _, err := s.db.Exec("INSERT INTO likes(user_id, target_type, target_id, value) VALUES(?,?,?,?)", userID, targetType, targetID, value)
        if err != nil {
            s.renderError(w, http.StatusInternalServerError)
            return
        }
	}
	if targetType == "post" {
		http.Redirect(w, r, fmt.Sprintf("/post/%d", targetID), http.StatusSeeOther)
	} else {
		var postID int
		s.db.QueryRow("SELECT post_id FROM comments WHERE id=?", targetID).Scan(&postID)
		http.Redirect(w, r, fmt.Sprintf("/post/%d", postID), http.StatusSeeOther)
	}
}

func (s *Server) handleCommentLike(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/comment/")
	parts := strings.Split(rest, "/")
    if len(parts) < 2 {
        s.renderError(w, http.StatusNotFound)
        return
    }
    id, err := strconv.Atoi(parts[0])
    if err != nil {
        s.renderError(w, http.StatusNotFound)
        return
    }
    switch parts[1] {
    case "like":
        s.handleLike(w, r, "comment", id, true)
    case "dislike":
        s.handleLike(w, r, "comment", id, false)
    default:
        s.renderError(w, http.StatusNotFound)
    }
}
