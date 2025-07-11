# E-Voting System

A secure electronic voting platform built with Node.js, Express, PostgreSQL, and Docker. This system leverages Public Key Infrastructure (PKI) for voter authentication, digital certificates, and end-to-end encrypted voting. The system features a web-based frontend for both voters and administrators.

## Features

- **User Registration**: Voters register with their details, upload a citizenship image, and provide a public key.
- **Admin Approval**: Admins review and approve/reject citizenship images and certificate requests.
- **Certificate Management**: PKI-based digital certificates are issued to approved voters.
- **Secure Login**: JWT-based authentication for both voters and admins.
- **Voting**: Authenticated voters cast encrypted votes, which are stored immutably in a blockchain-like ledger.
- **Vote Tallying**: Admins can decrypt and tally votes after the election.
- **Blockchain Ledger**: All votes and results are recorded in a tamper-evident ledger.
- **Audit & Verification**: Endpoints to verify individual votes, the election, and the integrity of the blockchain.
- **Dockerized**: Easy deployment with Docker and Docker Compose.

## Project Structure

```
cryptography/
  ├── server.js                # Main backend server (Express, API, DB, PKI logic)
  ├── package.json             # Node.js dependencies and scripts
  ├── Dockerfile               # Docker build instructions
  ├── docker-compose.yml       # Multi-container setup (app + PostgreSQL)
  ├── public/
  │   ├── index.html           # Main landing page
  │   ├── admin/
  │   │   └── index.html       # Admin dashboard frontend
  │   └── voting/
  │       └── index.html       # Voting portal frontend
  ├── uploads/                 # Uploaded citizenship images
  └── wait-for-it.sh           # Waits for DB before starting app
```

## Setup & Installation

### Prerequisites

- Docker & Docker Compose

### Quick Start
1. **Docker Image**
   ```
   docker pull d4rkwanderer/e-voting
   docker network create evoting-net
   docker run --name db --network evoting-net -e POSTGRES_PASSWORD=password -e POSTGRES_DB=evoting -p 5432:5432 -d postgres:14
   docker run -p 3000:3000 d4rkwanderer/secure_voting
   ```
### Alrernative 
1. **Clone the repository:**
   ```sh
   git clone <repo-url>
   cd cryptography
   ```

2. **Start the application:**
   ```sh
   docker-compose up --build
   ```

3. **Access the app:**
   - Voter portal: [http://localhost:3000/voting/](http://localhost:3000/voting/)
   - Admin portal: [http://localhost:3000/admin/](http://localhost:3000/admin/)

### Default Admin Account

- **Email:** "aayush@admin.com"
- **Password:** "adminadmin"

## API Endpoints

### Authentication & Registration

- `POST /api/register` — Register as a voter (with citizenship image and public key)
- `POST /api/login` — Voter login
- `POST /api/admin/login` — Admin login

### Admin Actions

- `POST /api/admin/approve-citizenship-image`
- `POST /api/admin/reject-citizenship-image`
- `GET /api/admin/pending-certificates`
- `POST /api/admin/approve-certificate`
- `POST /api/admin/reject-certificate`
- `POST /api/admin/revoke-certificate`
- `GET /api/admin/stats`
- `GET /api/admin/tally-votes`
- `POST /api/admin/publish-results`

### Voting

- `POST /api/request-certificate`
- `GET /api/auth-challenge/:voterID`
- `POST /api/authenticate`
- `POST /api/cast-vote`

### Verification & Audit

- `GET /api/ledger`
- `GET /api/verify-vote/:receiptID`
- `GET /api/verify-election`
- `GET /api/verify-blockchain`

## Database

- Uses PostgreSQL (see `docker-compose.yml` for credentials and DB name)
- Tables: `voters`, `certificate_requests`, `votes`, `ledger`

## Security

- Passwords hashed with bcrypt
- JWT for session management
- PKI for digital certificates and vote authentication
- Encrypted votes (AES-GCM), with keys managed per vote
- Blockchain-like ledger for tamper-evident vote storage

## Development

- Node.js v18 (see Dockerfile)
- Main entry: `server.js`
- To run locally without Docker, ensure PostgreSQL is running and update DB config in `server.js`.

