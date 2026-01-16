# vpnmanage_rflab

VPN User Management System for RF Lab

## Description

This is a terminal-based VPN user management application that provides a secure interface for managing VPN user accounts. The application uses ncurses for the terminal UI and OpenSSL for password hashing and cryptographic operations.

## Features

- Add new VPN users with secure password hashing (SHA-256)
- Delete existing users
- List all users with their status
- Verify user credentials
- Toggle user active/inactive status
- Persistent storage of user data

## Requirements

- GCC compiler
- ncurses library
- OpenSSL library (libssl and libcrypto)

On Ubuntu/Debian:
```bash
sudo apt-get install build-essential libncurses5-dev libssl-dev
```

On RHEL/CentOS/Fedora:
```bash
sudo yum install gcc ncurses-devel openssl-devel
```

## Building

To compile the application, use the provided gcc command:

```bash
gcc -o manage managevpnusers.c -lncurses -lssl -lcrypto
```

Or use the Makefile:

```bash
make
```

To clean build artifacts:

```bash
make clean
```

## Usage

Run the application:

```bash
./manage
```

The application will display a menu with the following options:

1. **Add User**: Create a new VPN user with username and password
2. **Delete User**: Remove an existing user
3. **List Users**: Display all users and their active status
4. **Verify User**: Test authentication for a username/password combination
5. **Toggle User Status**: Enable or disable a user account
6. **Save and Exit**: Save changes and quit the application

## Security

- Passwords are hashed using SHA-256 with random salt
- User credentials are stored in a binary database file (`vpnusers.db`)
- Passwords are never stored in plain text

## License

See LICENSE file for details.
