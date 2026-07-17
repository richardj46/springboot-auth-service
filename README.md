# Production-Ready Spring Boot Authentication Service

> A production-ready authentication and authorization service built with **Spring Boot**, **Spring Security**, **JWT**, **PostgreSQL**, and **Docker**. This project provides a secure foundation for modern backend applications with REST APIs, role-based access control, refresh tokens, database migrations, and production best practices.

![Java](https://img.shields.io/badge/Java-21-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen)
![Spring Security](https://img.shields.io/badge/Spring%20Security-6-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## Features

### Authentication

- User registration
- User login
- User logout
- JWT Access Token
- JWT Refresh Token
- Refresh token rotation
- Token revocation

### User Management

- Get current user profile
- Update profile
- Change password
- Delete account

### Authorization

- Role-Based Access Control (RBAC)
- User roles
- Method-level authorization
- Protected REST endpoints

### Account Security

- Email verification
- Forgot password
- Password reset
- Password hashing with BCrypt
- Login attempt limiting
- Account lockout
- Strong password policy

### Production Features

- Global exception handling
- Request validation
- DTO pattern
- Flyway database migrations
- Structured logging
- OpenAPI / Swagger documentation
- Docker support
- GitHub Actions CI
- Health checks
- Environment-based configuration

---

## Technology Stack

| Category | Technology |
|-----------|------------|
| Language | Java 21 |
| Framework | Spring Boot 3 |
| Security | Spring Security 6 |
| Authentication | JWT |
| Password Hashing | BCrypt |
| Database | PostgreSQL |
| ORM | Spring Data JPA (Hibernate) |
| Migration | Flyway |
| Validation | Jakarta Validation |
| Build Tool | Maven |
| Documentation | OpenAPI / Swagger |
| Testing | JUnit 5, Mockito, Testcontainers |
| Containerization | Docker & Docker Compose |

---

## Project Structure

```text
auth-service
├── src
│   ├── main
│   │   ├── java
│   │   │   └── com.example.auth
│   │   │       ├── auth
│   │   │       ├── user
│   │   │       ├── role
│   │   │       ├── security
│   │   │       ├── common
│   │   │       ├── config
│   │   │       └── exception
│   │   └── resources
│   │       ├── db
│   │       │   └── migration
│   │       ├── application.yml
│   │       ├── application-dev.yml
│   │       └── application-prod.yml
│   └── test
├── docker
├── .github
│   └── workflows
├── Dockerfile
├── docker-compose.yml
├── pom.xml
└── README.md
```

---

## REST APIs

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | User login |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/auth/verify-email` | Verify email |
| POST | `/api/v1/auth/forgot-password` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Reset password |

### User

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me` | Current user |
| PUT | `/api/v1/users/me` | Update profile |
| PUT | `/api/v1/users/password` | Change password |
| DELETE | `/api/v1/users/me` | Delete account |

### Administration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/users` | List users |
| PUT | `/api/v1/admin/users/{id}/role` | Update user role |
| PUT | `/api/v1/admin/users/{id}/disable` | Disable user |

---

## Authentication Flow

```text
Client
   │
   │ Login
   ▼
Auth Controller
   │
   ▼
Authentication Service
   │
   ▼
Spring Security
   │
   ▼
PostgreSQL
   │
   ▼
Generate JWT
   │
   ▼
Access Token + Refresh Token
```

---

## Database Schema

```text
users

roles

permissions

user_roles

role_permissions

refresh_tokens

password_reset_tokens

email_verification_tokens

login_attempts

audit_logs
```

---

## Getting Started

### Prerequisites

- Java 21
- Maven
- Docker
- Docker Compose
- PostgreSQL (optional when using Docker)

---

### Clone Repository

```bash
git clone https://github.com/your-username/auth-service.git

cd auth-service
```

---

### Run with Docker

```bash
docker compose up --build
```

The application will start together with PostgreSQL.

---

### Run Locally

Start PostgreSQL.

Configure your environment variables.

Run:

```bash
./mvnw spring-boot:run
```

or

```bash
mvn spring-boot:run
```

---

## Configuration

Example environment variables:

```env
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/authdb
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=password

JWT_SECRET=your-super-secret-key
JWT_ACCESS_TOKEN_EXPIRATION=900
JWT_REFRESH_TOKEN_EXPIRATION=2592000
```

---

## Security

This project follows common production security practices.

- JWT authentication
- Refresh token rotation
- BCrypt password hashing
- Role-based authorization
- Input validation
- Global exception handling
- Security headers
- HTTPS ready
- SQL injection protection through JPA
- Password reset tokens
- Email verification
- Login rate limiting
- Account locking

---

## Testing

Run all tests:

```bash
mvn test
```

Test types include:

- Unit tests
- Integration tests
- Repository tests
- Controller tests
- Security tests
- Testcontainers

---

## CI/CD

GitHub Actions automatically:

- Build project
- Run tests
- Verify code quality
- Build Docker image

---

## Roadmap

- [ ] Google OAuth2 Login
- [ ] GitHub OAuth2 Login
- [ ] Multi-factor Authentication (MFA)
- [ ] Redis token blacklist
- [ ] Email notifications
- [ ] Audit dashboard
- [ ] API rate limiting
- [ ] Multi-tenancy
- [ ] Session management
- [ ] Kubernetes deployment

---

## Documentation

Additional documentation:

- ARCHITECTURE.md
- API.md
- SECURITY.md
- DEPLOYMENT.md
- CONTRIBUTING.md
- CHANGELOG.md

---

## Why This Project?

Most tutorials stop after implementing login.

This project focuses on building an authentication service that reflects real-world backend engineering practices, including secure authentication, authorization, database migrations, testing, Docker deployment, and production-ready architecture. It is designed to serve as a reusable authentication service for Spring Boot applications.

---

## License

This project is licensed under the MIT License.