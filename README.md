[Communication Contract.docx](https://github.com/user-attachments/files/25455798/Communication.Contract.docx)
# Communication Contract – Account Management Service (REST + SQLite)

## Overview
The Account Management Service provides REST API functionality to register a new user, log in and receive a JWT token, view authenticated user profile (fullName, dob, address), and update authenticated user profile (fullName, dob, address, optional email). User data is stored using SQLite.

## Base URLs
Local: http://localhost:5001  
Deployed: https://account-management-service-a11d.onrender.com  
All endpoints are relative to the Base URL.

## Response Format (All Endpoints)
Success:
```json
{ "status": "ok", "data": { } }
```
Error:
```json
{ "status": "error", "error": { "code": "ERROR_CODE", "message": "Readable message" } }
```

## Endpoints
### Register
POST /register  
Example: POST https://account-management-service-a11d.onrender.com/register  
Header: Content-Type: application/json  
Body:
```json
{ "email": "user@example.com", "password": "Password123", "fullName": "John Doe", "dob": "YYYY-MM-DD", "address": "123 Main Street" }
```

### Login
POST /login  
Example: POST https://account-management-service-a11d.onrender.com/login  
Body:
```json
{ "email": "user@example.com", "password": "Password123" }
```
Success:
```json
{ "status": "ok", "data": { "token": "JWT_TOKEN" } }
```

### View Profile (Authenticated)
GET /profile  
Example: GET https://account-management-service-a11d.onrender.com/profile  
Header: Authorization: Bearer <token>

### Update Profile (Authenticated)
PATCH /profile  
Example: PATCH https://account-management-service-a11d.onrender.com/profile  
Headers: Authorization: Bearer <token>, Content-Type: application/json  
Body (partial updates allowed):
```json
{ "fullName": "New Name" }
```

## Authentication Rules
JWT token required for /profile endpoints. Missing or invalid token returns HTTP 401. Tokens expire after 30 minutes.

## Error Codes
INVALID_EMAIL_FORMAT, EMAIL_EXISTS, WEAK_PASSWORD, INVALID_DOB, INVALID_ADDRESS, USER_NOT_FOUND, INVALID_CREDENTIALS, UNAUTHORIZED, TOKEN_EXPIRED

## Contract Stability
This contract (endpoints, request structure, headers, response format, and error codes) must not change during the sprint without team agreement.
