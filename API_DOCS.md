Auth Service API Documentation

Overview
This is the API documentation for the Auth Service, which handles user authentication, authorization, and related operations.

Version: 1.0.0
API Specification: OpenAPI 3.1

Authentication
Method: OAuth2 Password Bearer
Token URL: /token
Authorization Header: Authorization: Bearer <token>

Most endpoints in this service require a valid JWT token passed in the Authorization header.

Endpoints

User Authentication Endpoints

Register User
- URL: /auth/register
- Method: POST
- Summary: Register a new user.
- Request Body:
{
  "$ref": "#/components/schemas/UserCreate"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/UserResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Login For Access Token
- URL: /auth/login
- Method: POST
- Summary: Login and obtain an access token.
- Request Body:
{
  "$ref": "#/components/schemas/Body_login_for_access_token_auth_login_post"
}
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Password Reset Request
- URL: /auth/password-reset-request
- Method: POST
- Summary: Request a password reset.
- Request Body:
{
  "$ref": "#/components/schemas/PasswordResetRequest"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Message"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Password Reset
- URL: /auth/password-reset
- Method: POST
- Summary: Reset the user’s password.
- Request Body:
{
  "$ref": "#/components/schemas/PasswordReset"
}
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Refresh Token
- URL: /auth/token-refresh
- Method: POST
- Summary: Refresh the access token.
- Request Body:
{
  "$ref": "#/components/schemas/TokenRefresh"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Token"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Enable 2FA
- URL: /auth/enable-2fa
- Method: POST
- Summary: Enable two-factor authentication (2FA).
- Request Body:
{
  "$ref": "#/components/schemas/Enable2FARequest"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Message"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Disable 2FA
- URL: /auth/disable-2fa
- Method: POST
- Summary: Disable two-factor authentication (2FA).
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Message"
    }

Verify 2FA
- URL: /auth/verify-2fa
- Method: POST
- Summary: Verify two-factor authentication (2FA) code.
- Request Body:
{
  "$ref": "#/components/schemas/Enable2FARequest"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Token"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Test 2FA
- URL: /auth/test-2fa
- Method: GET
- Summary: Test two-factor authentication (2FA).
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Message"
    }

Generate 2FA Code
- URL: /auth/generate-2fa-code
- Method: GET
- Summary: Generate a two-factor authentication (2FA) code.
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Enable2FARequest"
    }

Session Management Endpoints

List Sessions
- URL: /auth/sessions
- Method: GET
- Summary: List all active sessions for the user.
- Response:
  - 200 Successful Response:
    {
      "type": "array",
      "items": {
        "$ref": "#/components/schemas/SessionResponse"
      }
    }

Delete Session
- URL: /auth/sessions/{session_id}
- Method: DELETE
- Summary: Delete a session by its ID.
- Parameters:
  - session_id (integer): The ID of the session to delete.
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Verify User
- URL: /auth/verify-user/{username}
- Method: GET
- Summary: Verify the existence of a user by their username.
- Parameters:
  - username (string): The username to verify.
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/UserResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Update Profile
- URL: /auth/profile
- Method: PUT
- Summary: Update the user’s profile information.
- Request Body:
{
  "$ref": "#/components/schemas/UserUpdate"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/UserResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Admin Endpoints

List Users
- URL: /admin/users
- Method: GET
- Summary: List all users.
- Response:
  - 200 Successful Response:
    {}

Deactivate User
- URL: /admin/deactivate-user/{user_id}
- Method: PUT
- Summary: Deactivate a user by their ID.
- Parameters:
  - user_id (integer): The ID of the user to deactivate.
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/UserResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Activate User
- URL: /admin/activate-user/{user_id}
- Method: PUT
- Summary: Activate a user by their ID.
- Parameters:
  - user_id (integer): The ID of the user to activate.
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/UserResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Update Role
- URL: /admin/user/role
- Method: PUT
- Summary: Update the role of a user.
- Request Body:
{
  "$ref": "#/components/schemas/RoleUpdate"
}
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Delete User
- URL: /admin/user/{user_id}
- Method: DELETE
- Summary: Delete a user by their ID.
- Parameters:
  - user_id (integer): The ID of the user to delete.
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Lock Account
- URL: /admin/lock
- Method: POST
- Summary: Lock a user account.
- Request Body:
{
  "$ref": "#/components/schemas/LockAccountRequest"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Message"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Unlock Account
- URL: /admin/unlock
- Method: POST
- Summary: Unlock a user account.
- Request Body:
{
  "$ref": "#/components/schemas/UnlockAccountRequest"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/Message"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Register Admin
- URL: /admin/register
- Method: POST
- Summary: Register a new admin user.
- Request Body:
{
  "$ref": "#/components/schemas/AdminCreate"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/UserResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Admin Login
- URL: /admin/login
- Method: POST
- Summary: Login as an admin and obtain an access token.
- Request Body:
{
  "$ref": "#/components/schemas/AdminLogin"
}
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Vendor Endpoints

Register Vendor
- URL: /vendor/register_vendor
- Method: POST
- Summary: Register a new vendor.
- Request Body:
{
  "$ref": "#/components/schemas/VendorCreate"
}
- Response:
  - 200 Successful Response:
    {
      "$ref": "#/components/schemas/VendorResponse"
    }
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Vendor Login
- URL: /vendor/login
- Method: POST
- Summary: Login as a vendor and obtain an access token.
- Request Body:
{
  "$ref": "#/components/schemas/VendorLogin"
}
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Chatbot Endpoints

Create Chatbot Interaction
- URL: /chatbot/interact
- Method: POST
- Summary: Create a new chatbot interaction.
- Request Body:
{
  "type": "object",
  "title": "Chatbot"
}
- Response:
  - 200 Successful Response:
    {}
  - 422 Validation Error:
    {
      "$ref": "#/components/schemas/HTTPValidationError"
    }

Miscellaneous Endpoints

Root
- URL: /
- Method: GET
- Summary: Root endpoint.
- Response:
  - 200 Successful Response:
    {}

Protected
- URL: /protected
- Method: GET
- Summary: Protected endpoint.
- Response:
  - 200 Successful Response:
    {}
