Communication_LTD - Secure CRM System (Part A)


Project Overview
This is a secure Customer Relationship Management (CRM) system developed for Communication_LTD, a fictional telecommunications company. The project focuses on implementing "Secure by Design" principles, ensuring user data and credentials are protected using industry-standard cryptographic techniques.

🏗️ Tech Stack & Architecture
The project utilizes a containerized microservices architecture:

Backend: Developed in Python using the FastAPI framework for high-performance asynchronous API management.

Frontend: A responsive web interface built with HTML5, CSS3, and Vanilla JavaScript.

Database: MySQL 8.0 for persistent, relational data storage.

Containerization: Managed via Docker & Docker Compose for seamless environment replication across different machines.

🔒 Implemented Security Mechanisms (Part A)
To meet the rigorous requirements of "Part A", the following security features have been implemented:

1. Advanced Credential Protection
HMAC + Salt: Passwords are never stored in plain text. We use HMAC-SHA256 with a unique, randomly generated Salt for every user.

Configuration-Driven Policy: Password complexity rules are managed via config.py, enforcing:

Minimum length of 10 characters.

Mandatory use of uppercase, lowercase, numbers, and special characters.

Dictionary Attack Prevention: A blacklist of forbidden common words.

2. Account Security & Integrity
Account Lockout: The system tracks failed login attempts. After 3 failed tries, the account is automatically locked (is_locked = True) to prevent Brute Force attacks.

Password History: Users cannot reuse their last 3 passwords. The system maintains a password_history table to enforce this.

3. Secure Password Recovery
Double Authentication: Password reset requires both a valid Username and the registered Email address.

SHA-1 Tokenization: Upon validation, the system generates a random SHA-1 token to authorize the password change process.

4. Injection Prevention
Parameterized Queries: All database interactions use prepared statements/parameterized queries to negate the risk of SQL Injection (SQLi).

📂 Project Structure
/backend: Contains the API logic (main.py), security utilities (security.py), and settings (config.py).

/frontend: Contains all client-side assets (index.html, system.html, customers.html, etc.).

docker-compose.yml: Orchestrates the interaction between the Python server and the MySQL database.

🚀 Getting Started for Team Members
To run the project locally, ensure you have Docker Desktop installed, then execute:

docker-compose down
docker-compose up --build

Once the containers are running:

Frontend: Access the UI at http://localhost:3000

API Docs: View the interactive Swagger documentation at http://localhost:5000/docs
