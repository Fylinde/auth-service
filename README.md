# Auth Service

## Overview

The Auth Service is a core component of our microservices architecture, responsible for managing user authentication, authorization, and related security operations. This service provides essential functionalities such as user registration, login, password management, two-factor authentication (2FA), and session management.

## Features

- **User Registration**: Allows new users to register by providing basic information such as username, email, and password.
- **User Login**: Enables users to log in and obtain access tokens for secure access to other services.
- **Password Management**: Includes features for requesting a password reset and updating the password.
- **Two-Factor Authentication (2FA)**: Provides additional security by allowing users to enable and verify 2FA.
- **Session Management**: Manages user sessions, including listing active sessions and deleting specific sessions.
- **Admin Operations**: Includes administrative functionalities such as managing user accounts, locking/unlocking accounts, and updating user roles.
- **Vendor and Chatbot Integration**: Supports vendor-specific operations and integrates with chatbot services for automated interactions.

## Purpose

The Auth Service is designed to secure the application by controlling access to various resources through robust authentication and authorization mechanisms. It acts as the gateway for user identity management, ensuring that only authenticated and authorized users can interact with protected resources.

## Usage

This service will be used by other microservices in the architecture to authenticate users and verify their permissions before granting access to resources. Additionally, it provides endpoints for managing user accounts and ensuring secure interactions within the application.

## Endpoints Overview

For a detailed list of available endpoints, including request and response formats, please refer to the [API Documentation](./API_DOCS.md).

## Technologies

- **OAuth2**: Used for secure authorization, enabling users to log in and receive tokens that provide access to other services.
- **JSON Web Tokens (JWT)**: Utilized for securely transmitting information between the client and server, ensuring that data is both verifiable and tamper-proof.
- **REST API**: The service exposes a RESTful API for interaction with other services and clients.

## Setup and Configuration

To set up the Auth Service, follow these steps:

1. **Clone the repository**:  
   ```bash
   git clone https://github.com/your-org/auth-service.git

2. **Install dependencies**:
   ```bash
   cd auth-service
   npm install
3. **Configure environment variables**:
   Create a .env file and configure the necessary environment variables such as database connection strings, OAuth2 secrets, etc.
4. **Run the service**:
   ```bash
   docker-compose up --build
