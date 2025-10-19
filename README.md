# Electronic Voting System

## Setup

1. Clone the repository
2. Run `docker-compose up --build`
3. Access your app at https://localhost:5000

## Features

- Multi-factor authentication (TOTP)
- Role-Based Access Control (RBAC)
- AES-256 vote encryption
- Ed25519 digital signatures
- Argon2 password hashing
- Input validation and sanitization
- Immutable audit logging (tamper-evident)
- Rate limiting and security headers

## Security Requirements

Each file and function is annotated with `# SR-xx` comments matching assignment requirements.

## Contributors

Details of team members and assigned requirements will be included.

## Testing

Run `pytest` in the `tests/` directory.
