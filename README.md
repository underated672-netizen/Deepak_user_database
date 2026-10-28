# ARAH Mini Auth & Authz System

A secure backend authentication and authorization system built with **FastAPI** and **SQLite**, featuring JWT-based token authentication and strict role/user access control.

## Features
- User Registration (`/register`) with secure password hashing (SHA-256 + Salt).
- User Login (`/login`) returning a secure JWT access token.
- Secure Profile Viewing (`GET /profile/{user_id}`) restricted to the logged-in user.
- Profile Updating (`PUT /profile/{user_id}`) with strict authorization checks to prevent unauthorized cross-user modifications.

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <https://github.com/underated672-netizen/Deepak_user_database>
   cd Deepak_user_database
