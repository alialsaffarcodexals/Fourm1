# Fourm1

A minimal web forum implemented in Go with SQLite storage and session-based authentication.

## Features
- User registration and login with cookie-based sessions
- Create posts with one or more categories
- Comment on posts
- Like or dislike posts and comments
- Filter posts by category
- Responsive interface styled with CSS served from `/static`
- Dockerfile for containerized deployment

## Running
```
go run .
```
The server listens on `:8080` and stores data in `forum.db`.

## Tests
```
go test ./...
```
