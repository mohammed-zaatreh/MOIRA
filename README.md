# MOIRA

MOIRA is a Java 17 backend application built with Spring Boot, Spring Web MVC, and Spring Data JPA, using PostgreSQL as its primary database.

---

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [1) Clone the repository](#1-clone-the-repository)
  - [2) Configure the database](#2-configure-the-database)
  - [3) Configure application properties](#3-configure-application-properties)
  - [4) Run the application](#4-run-the-application)
- [Configuration](#configuration)
- [Build and Test](#build-and-test)
- [Database Notes](#database-notes)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

MOIRA is a Spring-based service designed around a layered backend architecture (controller/service/repository/model patterns are expected in a standard Spring Boot codebase).  
It uses:

- **Spring Web MVC** for REST endpoints
- **Spring Data JPA** for persistence
- **PostgreSQL** for relational data storage
- **Maven** for build and dependency management

---

## Tech Stack

- **Language:** Java 17
- **Framework:** Spring Boot
- **Modules/Libraries:**
  - spring-boot-starter-webmvc
  - spring-boot-starter-data-jpa
  - PostgreSQL JDBC driver
  - Lombok
- **Build Tool:** Maven (includes Maven Wrapper)
- **Database:** PostgreSQL

---

## Project Structure

Current top-level structure (from repository root):

- `.mvn/` – Maven wrapper support files
- `mvnw`, `mvnw.cmd` – Maven wrapper scripts
- `pom.xml` – Project definition and dependencies
- `application.properties` – root-level app properties
- `src/` – source code and resources
- CSV output files (batch results):
  - `moira_batch_results_1767651498762.csv`
  - `moira_batch_results_1767654546332.csv`

> Recommendation: keep runtime-generated CSV outputs in a dedicated directory (e.g., `output/`) and add ignore rules as needed.

---

## Prerequisites

Before running locally, ensure you have:

- **JDK 17**
- **PostgreSQL 13+** (or compatible)
- **Git**
- (Optional) IntelliJ IDEA / VS Code with Java extensions

---

## Getting Started

### 1) Clone the repository

```bash
git clone https://github.com/mohammed-zaatreh/MOIRA.git
cd MOIRA
```

### 2) Configure the database

Create a PostgreSQL database (default name in config is `moira_db`):

```sql
CREATE DATABASE moira_db;
```

Make sure your PostgreSQL server is running and reachable at `localhost:5432` (or adjust config accordingly).

### 3) Configure application properties

The repository currently contains database credentials in `application.properties`.  
Update them for your local environment.

Example:

```properties
spring.application.name=MOIRA

spring.datasource.url=jdbc:postgresql://localhost:5432/moira_db
spring.datasource.username=postgres
spring.datasource.password=your_password_here

spring.jpa.hibernate.ddl-auto=validate
spring.jpa.show-sql=true
```

### 4) Run the application

Using Maven Wrapper (recommended):

```bash
./mvnw spring-boot:run
```

On Windows:

```powershell
mvnw.cmd spring-boot:run
```

If successful, the app starts on the default Spring port (`8080`) unless overridden.

---

## Configuration

Key properties:

- `spring.datasource.url` – PostgreSQL JDBC URL
- `spring.datasource.username` – DB user
- `spring.datasource.password` – DB password
- `spring.jpa.hibernate.ddl-auto` – schema mode (`validate`/`update`, etc.)
- `spring.jpa.show-sql` – SQL logging toggle

### About `ddl-auto`

Two values appear in repository configs:

- `update` (root `application.properties`)
- `validate` (`src/main/resources/application.properties`)

For predictable environments, prefer **one source of truth** and keep `src/main/resources/application.properties` as the canonical runtime config.

---

## Build and Test

Build the project:

```bash
./mvnw clean package
```

Run tests:

```bash
./mvnw test
```

---

## Database Notes

- Project uses Spring Data JPA with PostgreSQL.
- Based on current properties, schema handling may rely on validation/custom scripts.
- Ensure your schema exists before launching if using `ddl-auto=validate`.

---

## Troubleshooting

### Application fails to connect to DB
- Verify PostgreSQL is running.
- Confirm `spring.datasource.url`, username, and password.
- Check DB exists (`moira_db`) and user permissions are correct.

### Port already in use
Run with a different port:

```bash
./mvnw spring-boot:run -Dspring-boot.run.arguments=--server.port=8081
```

### Maven/JDK issues
- Confirm `java -version` outputs Java 17.
- Run `./mvnw -v` to confirm Maven wrapper works.

---

## Security Notes

- Do **not** commit real credentials.
- Move secrets to environment variables or profiles:

```properties
spring.datasource.password=${DB_PASSWORD}
```

Then set:

```bash
export DB_PASSWORD=your_password
```

---

## Roadmap

Suggested next improvements:

- Add API documentation (OpenAPI/Swagger)
- Add Docker Compose for app + PostgreSQL
- Add migration tool (Flyway or Liquibase)
- Add CI workflow (build + test on PRs)
- Add environment profiles (`dev`, `test`, `prod`)
- Expand integration tests

---

## Contributing

1. Fork the repo
2. Create a feature branch
3. Commit with clear messages
4. Open a Pull Request with:
   - problem statement
   - implementation details
   - test evidence

---

## License

No license is currently declared in `pom.xml` or repository metadata.

If you want open-source usage, add a license file (e.g., MIT, Apache-2.0) and update this section.
