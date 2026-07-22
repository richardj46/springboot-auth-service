# Spring Boot Auth Service

A production-ready authentication and authorization service built with **Spring Boot 3**, **Spring Security**, **JWT**, and **PostgreSQL**.

This project provides secure user authentication for modern web applications using short-lived JWT access tokens and rotating refresh tokens. It is designed as the backend for the **springboot-auth-web** React frontend.

---

## Features

### Authentication

* User registration
* User login
* JWT access tokens
* Refresh token rotation
* Secure logout
* Stateless authentication
* Password hashing with BCrypt

### Spring Security

* Built on Spring Security
* JWT authentication filter
* Role-based authorization
* Protected REST endpoints
* Security filter chain configuration
* CORS configuration for frontend integration

### Refresh Token Strategy

* Short-lived JWT access token
* Opaque refresh token
* Refresh token rotation
* Refresh token revocation on logout
* Secure HttpOnly cookie support
* Compatible with SPA applications

### Database

* PostgreSQL
* Spring Data JPA
* Hibernate ORM

### Frontend Integration

Integrated with the companion project:

* **springboot-auth-web**
* React
* Vite
* TypeScript

Authentication flow:

1. User logs in.
2. Backend returns JWT access token.
3. Backend sets refresh token cookie.
4. Frontend stores access token in memory.
5. Protected requests use:

Authorization: Bearer <access_token>

6. When expired, frontend calls:

```
POST /api/auth/refresh
```

7. Backend rotates the refresh token and returns a new access token.

---

## Technology Stack

| Technology      | Version         |
| --------------- | --------------- |
| Java            | 21              |
| Spring Boot     | 3.x             |
| Spring Security | 6.x             |
| Spring Data JPA | Latest          |
| Hibernate       | 6.x             |
| PostgreSQL      | 16+             |
| Maven           | 3.9+            |
| JWT             | JJWT            |
| BCrypt          | Spring Security |

---

## Project Structure

```
src
└── main
    ├── java
    │   └── com.richardj46.authservice
    │       ├── config
    │       ├── controller
    │       ├── dto
    │       ├── entity
    │       ├── repository
    │       ├── security
    │       ├── service
    │       └── util
    └── resources
        └── application.yml
```

---

## API Endpoints

### Authentication

| Method | Endpoint             | Description          |
| ------ | -------------------- | -------------------- |
| POST   | `/api/auth/register` | Register a new user  |
| POST   | `/api/auth/login`    | Login                |
| POST   | `/api/auth/refresh`  | Refresh access token |
| POST   | `/api/auth/logout`   | Logout               |

---

## Environment Variables

```
DATABASE_URL=
DATABASE_USERNAME=
DATABASE_PASSWORD=

JWT_SECRET=
JWT_EXPIRATION=

REFRESH_TOKEN_EXPIRATION=
```

Example:

```
DATABASE_URL=jdbc:postgresql://localhost:5432/authdb
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=password

JWT_SECRET=your-256-bit-secret
JWT_EXPIRATION=900000

REFRESH_TOKEN_EXPIRATION=604800000
```

---

## Running the Project

### Clone

```
git clone https://github.com/<username>/springboot-auth-service.git
```

### Configure Environment

Create your environment variables or configure them in your IDE.

### Run

```
./mvnw spring-boot:run
```

or

```
mvn spring-boot:run
```

---

## Authentication Flow

```
Register
      │
      ▼
 Login
      │
      ▼
Access JWT + Refresh Cookie
      │
      ▼
Protected API
      │
      ▼
JWT Expired
      │
      ▼
POST /api/auth/refresh
      │
      ▼
New Access JWT
      │
      ▼
Continue
```

---

## Security Design

* Stateless authentication
* JWT access tokens
* Rotating refresh tokens
* BCrypt password hashing
* Spring Security authorization
* Secure cookie support
* Refresh token revocation
* CSRF-safe authentication strategy for SPA clients
* CORS restricted to trusted frontend origins

---

## Companion Frontend

Frontend repository:

**springboot-auth-web**

Built with:

* React
* Vite
* TypeScript
* Axios
* React Router

---

## Roadmap

* Email verification
* Forgot password
* Password reset
* Account lockout
* Login attempt throttling
* Two-factor authentication (2FA)
* OAuth2 login (Google, GitHub)
* Role & permission management
* Admin dashboard
* Audit logging
* User profile management

---

## License

MIT License
