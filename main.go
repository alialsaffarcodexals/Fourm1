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

    http.HandleFunc("/", s.handleIndex)
    http.HandleFunc("/register", s.handleRegister)
    http.HandleFunc("/login", s.handleLogin)
    http.HandleFunc("/logout", s.handleLogout)
    http.HandleFunc("/post/", s.handlePost)
    http.HandleFunc("/comment/", s.handleCommentLike)

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
        http.Error(w, err.Error(), 500)
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
            http.Error(w, err.Error(), 500)
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
    s.templates.ExecuteTemplate(w, "index.html", data)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        s.templates.ExecuteTemplate(w, "register.html", nil)
    case http.MethodPost:
        email := r.FormValue("email")
        username := r.FormValue("username")
        password := r.FormValue("password")
        if email == "" || username == "" || password == "" {
            http.Error(w, "missing fields", 400)
            return
        }
        hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, err.Error(), 500)
            return
        }
        _, err = s.db.Exec("INSERT INTO users(email, username, password) VALUES(?,?,?)", email, username, string(hashed))
        if err != nil {
            http.Error(w, err.Error(), 400)
            return
        }
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    default:
        http.Error(w, "method not allowed", 405)
    }
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        s.templates.ExecuteTemplate(w, "login.html", nil)
    case http.MethodPost:
        email := r.FormValue("email")
        password := r.FormValue("password")
        var id int
        var hashed string
        err := s.db.QueryRow("SELECT id, password FROM users WHERE email=?", email).Scan(&id, &hashed)
        if err != nil {
            http.Error(w, "invalid credentials", 400)
            return
        }
        if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) != nil {
            http.Error(w, "invalid credentials", 400)
            return
        }
        token := uuid.New().String()
        s.mu.Lock()
        s.sessions[token] = Session{userID: id, expires: time.Now().Add(24 * time.Hour)}
        s.mu.Unlock()
        http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", Expires: time.Now().Add(24 * time.Hour)})
        http.Redirect(w, r, "/", http.StatusSeeOther)
    default:
        http.Error(w, "method not allowed", 405)
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
        http.NotFound(w, r)
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
        http.NotFound(w, r)
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
        http.Error(w, err.Error(), 500)
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
            http.Error(w, err.Error(), 500)
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
    s.templates.ExecuteTemplate(w, "post.html", data)
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
        type Cat struct{ ID int; Name string }
        var cats []Cat
        for rows.Next() {
            var c Cat
            rows.Scan(&c.ID, &c.Name)
            cats = append(cats, c)
        }
        s.templates.ExecuteTemplate(w, "create_post.html", cats)
    case http.MethodPost:
        title := r.FormValue("title")
        content := r.FormValue("content")
        if title == "" || content == "" {
            http.Error(w, "missing fields", 400)
            return
        }
        res, err := s.db.Exec("INSERT INTO posts(user_id, title, content) VALUES(?,?,?)", userID, title, content)
        if err != nil {
            http.Error(w, err.Error(), 500)
            return
        }
        postID, _ := res.LastInsertId()
        cats := r.Form["categories"]
        for _, c := range cats {
            s.db.Exec("INSERT INTO post_categories(post_id, category_id) VALUES(?,?)", postID, c)
        }
        http.Redirect(w, r, fmt.Sprintf("/post/%d", postID), http.StatusSeeOther)
    default:
        http.Error(w, "method not allowed", 405)
    }
}

func (s *Server) handleAddComment(w http.ResponseWriter, r *http.Request, postID int) {
    userID, ok := s.currentUser(r)
    if !ok {
        http.Error(w, "unauthorized", 401)
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", 405)
        return
    }
    content := r.FormValue("content")
    if strings.TrimSpace(content) == "" {
        http.Error(w, "empty comment", 400)
        return
    }
    if _, err := s.db.Exec("INSERT INTO comments(post_id, user_id, content) VALUES(?,?,?)", postID, userID, content); err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    http.Redirect(w, r, fmt.Sprintf("/post/%d", postID), http.StatusSeeOther)
}

func (s *Server) handleLike(w http.ResponseWriter, r *http.Request, targetType string, targetID int, isLike bool) {
    userID, ok := s.currentUser(r)
    if !ok {
        http.Error(w, "unauthorized", 401)
        return
    }
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", 405)
        return
    }
    value := -1
    if isLike {
        value = 1
    }
    var current int
    err := s.db.QueryRow("SELECT value FROM likes WHERE user_id=? AND target_type=? AND target_id=?", userID, targetType, targetID).Scan(&current)
    if err != nil && !errors.Is(err, sql.ErrNoRows) {
        http.Error(w, err.Error(), 500)
        return
    }
    if current == value {
        s.db.Exec("DELETE FROM likes WHERE user_id=? AND target_type=? AND target_id=?", userID, targetType, targetID)
    } else if current == -value {
        s.db.Exec("UPDATE likes SET value=? WHERE user_id=? AND target_type=? AND target_id=?", value, userID, targetType, targetID)
    } else {
        _, err := s.db.Exec("INSERT INTO likes(user_id, target_type, target_id, value) VALUES(?,?,?,?)", userID, targetType, targetID, value)
        if err != nil {
            http.Error(w, err.Error(), 500)
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
        http.NotFound(w, r)
        return
    }
    id, err := strconv.Atoi(parts[0])
    if err != nil {
        http.NotFound(w, r)
        return
    }
    switch parts[1] {
    case "like":
        s.handleLike(w, r, "comment", id, true)
    case "dislike":
        s.handleLike(w, r, "comment", id, false)
    default:
        http.NotFound(w, r)
    }
}

