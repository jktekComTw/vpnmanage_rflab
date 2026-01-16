#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <time.h>

#define MAX_USERS 100
#define MAX_USERNAME 32
#define MAX_PASSWORD 64
#define SALT_SIZE 16
#define HASH_SIZE 32
#define USER_FILE "vpnusers.db"

typedef struct {
    char username[MAX_USERNAME];
    unsigned char salt[SALT_SIZE];
    unsigned char hash[HASH_SIZE];
    int active;
} VPNUser;

VPNUser users[MAX_USERS];
int user_count = 0;

void hash_password(const char *password, const unsigned char *salt, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    unsigned int len;
    
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salt, SALT_SIZE);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, output, &len);
    EVP_MD_CTX_free(mdctx);
}

void generate_salt(unsigned char *salt) {
    RAND_bytes(salt, SALT_SIZE);
}

int load_users() {
    FILE *fp = fopen(USER_FILE, "rb");
    if (fp == NULL) {
        return 0;
    }
    
    user_count = fread(users, sizeof(VPNUser), MAX_USERS, fp);
    fclose(fp);
    return user_count;
}

int save_users() {
    FILE *fp = fopen(USER_FILE, "wb");
    if (fp == NULL) {
        return -1;
    }
    
    fwrite(users, sizeof(VPNUser), user_count, fp);
    fclose(fp);
    return 0;
}

int find_user(const char *username) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

int add_user(const char *username, const char *password) {
    if (user_count >= MAX_USERS) {
        return -1;
    }
    
    if (find_user(username) != -1) {
        return -2;
    }
    
    VPNUser *user = &users[user_count];
    strncpy(user->username, username, MAX_USERNAME - 1);
    user->username[MAX_USERNAME - 1] = '\0';
    
    generate_salt(user->salt);
    hash_password(password, user->salt, user->hash);
    user->active = 1;
    
    user_count++;
    return 0;
}

int delete_user(const char *username) {
    int idx = find_user(username);
    if (idx == -1) {
        return -1;
    }
    
    for (int i = idx; i < user_count - 1; i++) {
        users[i] = users[i + 1];
    }
    user_count--;
    return 0;
}

int verify_password(const char *username, const char *password) {
    int idx = find_user(username);
    if (idx == -1) {
        return 0;
    }
    
    unsigned char hash[HASH_SIZE];
    hash_password(password, users[idx].salt, hash);
    
    return memcmp(hash, users[idx].hash, HASH_SIZE) == 0;
}

void display_menu() {
    clear();
    mvprintw(0, 0, "=== VPN User Management System ===");
    mvprintw(2, 0, "1. Add User");
    mvprintw(3, 0, "2. Delete User");
    mvprintw(4, 0, "3. List Users");
    mvprintw(5, 0, "4. Verify User");
    mvprintw(6, 0, "5. Toggle User Status");
    mvprintw(7, 0, "6. Save and Exit");
    mvprintw(9, 0, "Select option: ");
    refresh();
}

void list_users() {
    clear();
    mvprintw(0, 0, "=== VPN Users ===");
    mvprintw(1, 0, "%-20s %-10s", "Username", "Status");
    mvprintw(2, 0, "----------------------------------------");
    
    for (int i = 0; i < user_count; i++) {
        mvprintw(3 + i, 0, "%-20s %-10s", 
                 users[i].username, 
                 users[i].active ? "Active" : "Inactive");
    }
    
    mvprintw(4 + user_count, 0, "Press any key to continue...");
    refresh();
    getch();
}

void add_user_interactive() {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    
    clear();
    mvprintw(0, 0, "=== Add New User ===");
    mvprintw(2, 0, "Username: ");
    refresh();
    echo();
    getnstr(username, MAX_USERNAME - 1);
    
    mvprintw(3, 0, "Password: ");
    refresh();
    noecho();
    getnstr(password, MAX_PASSWORD - 1);
    
    int result = add_user(username, password);
    if (result == 0) {
        mvprintw(5, 0, "User added successfully!");
    } else if (result == -1) {
        mvprintw(5, 0, "Error: Maximum users reached!");
    } else if (result == -2) {
        mvprintw(5, 0, "Error: User already exists!");
    }
    
    mvprintw(6, 0, "Press any key to continue...");
    refresh();
    getch();
}

void delete_user_interactive() {
    char username[MAX_USERNAME];
    
    clear();
    mvprintw(0, 0, "=== Delete User ===");
    mvprintw(2, 0, "Username: ");
    refresh();
    echo();
    getnstr(username, MAX_USERNAME - 1);
    noecho();
    
    int result = delete_user(username);
    if (result == 0) {
        mvprintw(4, 0, "User deleted successfully!");
    } else {
        mvprintw(4, 0, "Error: User not found!");
    }
    
    mvprintw(5, 0, "Press any key to continue...");
    refresh();
    getch();
}

void verify_user_interactive() {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    
    clear();
    mvprintw(0, 0, "=== Verify User ===");
    mvprintw(2, 0, "Username: ");
    refresh();
    echo();
    getnstr(username, MAX_USERNAME - 1);
    
    mvprintw(3, 0, "Password: ");
    refresh();
    noecho();
    getnstr(password, MAX_PASSWORD - 1);
    
    if (verify_password(username, password)) {
        mvprintw(5, 0, "Authentication successful!");
    } else {
        mvprintw(5, 0, "Authentication failed!");
    }
    
    mvprintw(6, 0, "Press any key to continue...");
    refresh();
    getch();
}

void toggle_user_status() {
    char username[MAX_USERNAME];
    
    clear();
    mvprintw(0, 0, "=== Toggle User Status ===");
    mvprintw(2, 0, "Username: ");
    refresh();
    echo();
    getnstr(username, MAX_USERNAME - 1);
    noecho();
    
    int idx = find_user(username);
    if (idx != -1) {
        users[idx].active = !users[idx].active;
        mvprintw(4, 0, "User status changed to: %s", 
                 users[idx].active ? "Active" : "Inactive");
    } else {
        mvprintw(4, 0, "Error: User not found!");
    }
    
    mvprintw(5, 0, "Press any key to continue...");
    refresh();
    getch();
}

int main() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    
    load_users();
    
    int choice;
    int running = 1;
    
    while (running) {
        display_menu();
        choice = getch() - '0';
        
        switch (choice) {
            case 1:
                add_user_interactive();
                break;
            case 2:
                delete_user_interactive();
                break;
            case 3:
                list_users();
                break;
            case 4:
                verify_user_interactive();
                break;
            case 5:
                toggle_user_status();
                break;
            case 6:
                save_users();
                running = 0;
                break;
        }
    }
    
    endwin();
    printf("VPN user database saved. Goodbye!\n");
    return 0;
}
