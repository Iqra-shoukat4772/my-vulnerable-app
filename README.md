# User Management System - Cybersecurity Project

## Overview
This project was completed as part of a Cybersecurity Internship at DevelopersHub Corporation.
A simple User Management System was built, analyzed for vulnerabilities, and secured using industry-standard tools.

## Vulnerabilities Found
| # | Vulnerability | Risk Level |
|---|--------------|------------|
| 1 | XSS Attack | High |
| 2 | Weak Password Storage | Critical |
| 3 | No Input Validation | High |
| 4 | SQL Injection | Critical |

## Security Fixes Applied
| # | Fix | Library Used |
|---|-----|-------------|
| 1 | XSS Prevention | validator |
| 2 | Password Hashing | bcrypt |
| 3 | Input Validation | validator |
| 4 | JWT Authentication | jsonwebtoken |
| 5 | Secure HTTP Headers | helmet |
| 6 | Security Logging | winston |

## Technologies Used
- Node.js
- Express.js
- bcrypt
- jsonwebtoken
- validator
- helmet
- winston

## How to Run
1. Clone the repository
2. Run `npm install`
3. Run `node app.js`
4. Open `http://localhost:3000`

## Author
Iqra Khurram
Cybersecurity Intern - DevelopersHub Corporation
