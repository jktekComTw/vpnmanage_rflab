#include <ncurses.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_ROWS 100
#define NUM_COLS 7
#define FILE_NAME "/etc/ppp/chap-secrets"



typedef struct {
    char client[64];
    char server[64];
    char secret[64];
    char secret_md5[33];
    char ip[32];
    char date[32];
    char months[16];
    char expired[16];
    int is_expired;
} Entry;

Entry entries[MAX_ROWS];
int num_entries = 0;

int col_pos[] = {0, 12, 20, 56, 64, 76, 84};
int col_width[] = {12, 8, 36, 8, 12, 8, 10};

void md5_hash(const char *str, char *output) {
    char cmd[256];
    FILE *fp;
    snprintf(cmd, sizeof(cmd), "echo -n '%s' | md5sum | cut -d' ' -f1", str);
    fp = popen(cmd, "r");
    if (fp) {
        fgets(output, 33, fp);
        output[32] = '\0';
        pclose(fp);
    }
}

void calculate_expired(Entry *entry) {
    int month, day, year;
    int months_to_add;
    
    if (sscanf(entry->date, "%d/%d/%d", &month, &day, &year) != 3) {
        strcpy(entry->expired, "N/A");
        entry->is_expired = 0;
        return;
    }
    
    if (entry->months[0] == '~') {
        strcpy(entry->expired, "Never");
        entry->is_expired = 0;
        return;
    }
    
    months_to_add = atoi(entry->months);
    if (months_to_add <= 0) {
        strcpy(entry->expired, "N/A");
        entry->is_expired = 0;
        return;
    }
    
    struct tm expiry_tm = {0};
    expiry_tm.tm_year = year - 1900;
    expiry_tm.tm_mon = month - 1 + months_to_add;
    expiry_tm.tm_mday = day;
    
    mktime(&expiry_tm);
    
    time_t now = time(NULL);
    time_t expiry_time = mktime(&expiry_tm);
    
    // Show expiry date
    snprintf(entry->expired, 16, "%02d/%02d/%04d",
             expiry_tm.tm_mon + 1,
             expiry_tm.tm_mday,
             expiry_tm.tm_year + 1900);
    
    // Set expired flag
    if (expiry_time < now) {
        entry->is_expired = 1;
    } else {
        entry->is_expired = 0;
    }
}

void save_file() {
    FILE *fp = fopen(FILE_NAME, "w");
    if (fp == NULL) return;
    
    fprintf(fp, "# Secrets for authentication using CHAP\n");
    fprintf(fp, "# client\tserver\tsecret\t\t\t\tIP addresses\n");
    
    for (int i = 0; i < num_entries; i++) {
        fprintf(fp, "%s\t%s\t\"%s\"\t%s\t#%s\t%s\n",
                entries[i].client,
                entries[i].server,
                entries[i].secret,
                entries[i].ip,
                entries[i].date,
                entries[i].months);
    }
    fclose(fp);
}

int get_input(char *buffer, int max_len, int y, int x, const char *prompt, int is_password) {
    int pos = 0;
    int ch;
    buffer[0] = '\0';
    
    mvprintw(y, 0, "%s", prompt);
    clrtoeol();
    move(y, x);
    refresh();
    
    while (1) {
        ch = getch();
        
        if (ch == 27) {
            return 0;
        } else if (ch == 10 || ch == KEY_ENTER) {
            return 1;
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (pos > 0) {
                buffer[--pos] = '\0';
            }
        } else if (pos < max_len && ch >= 32 && ch <= 126) {
            buffer[pos++] = ch;
            buffer[pos] = '\0';
        }
        
        if (is_password) {
            char masked[64];
            memset(masked, '*', pos);
            masked[pos] = '\0';
            mvprintw(y, x, "%-40s", masked);
        } else {
            mvprintw(y, x, "%-40s", buffer);
        }
        refresh();
    }
}

void add_new_entry() {
    if (num_entries >= MAX_ROWS) {
        attron(COLOR_PAIR(3));
        mvprintw(num_entries + 10, 0, "Maximum entries reached! Press any key...");
        attroff(COLOR_PAIR(3));
        refresh();
        getch();
        return;
    }
    
    Entry new_entry;
    char confirm[64];
    int base_y = num_entries + 6;
    
    curs_set(1);
    
    for (int i = 0; i < 12; i++) {
        move(base_y + i, 0);
        clrtoeol();
    }
    
    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(base_y, 0, "=== Add New Entry ===");
    attroff(COLOR_PAIR(2) | A_BOLD);
    
    mvprintw(base_y + 10, 0, "Enter: Confirm | Esc: Cancel");
    
    if (!get_input(new_entry.client, 63, base_y + 1, 20, "Client:             ", 0)) {
        curs_set(0);
        return;
    }
    
    strcpy(new_entry.server, "l2tpd");
    if (!get_input(new_entry.server, 63, base_y + 2, 20, "Server [l2tpd]:     ", 0)) {
        curs_set(0);
        return;
    }
    if (strlen(new_entry.server) == 0) {
        strcpy(new_entry.server, "l2tpd");
    }
    
    if (!get_input(new_entry.secret, 63, base_y + 3, 20, "Password:           ", 1)) {
        curs_set(0);
        return;
    }
    
    if (!get_input(confirm, 63, base_y + 4, 20, "Confirm Password:   ", 1)) {
        curs_set(0);
        return;
    }
    
    if (strcmp(new_entry.secret, confirm) != 0) {
        attron(COLOR_PAIR(3));
        mvprintw(base_y + 6, 0, "Passwords do not match! Press any key...");
        attroff(COLOR_PAIR(3));
        refresh();
        getch();
        curs_set(0);
        return;
    }
    
    strcpy(new_entry.ip, "*");
    if (!get_input(new_entry.ip, 31, base_y + 5, 20, "IP [*]:             ", 0)) {
        curs_set(0);
        return;
    }
    if (strlen(new_entry.ip) == 0) {
        strcpy(new_entry.ip, "*");
    }
    
    if (!get_input(new_entry.date, 31, base_y + 6, 20, "Date (MM/DD/YYYY):  ", 0)) {
        curs_set(0);
        return;
    }
    
    if (!get_input(new_entry.months, 15, base_y + 7, 20, "Months:             ", 0)) {
        curs_set(0);
        return;
    }
    
    md5_hash(new_entry.secret, new_entry.secret_md5);
    calculate_expired(&new_entry);
    
    entries[num_entries] = new_entry;
    num_entries++;
    
    save_file();
    
    attron(COLOR_PAIR(4));
    mvprintw(base_y + 9, 0, "Entry added successfully! Press any key...");
    attroff(COLOR_PAIR(4));
    refresh();
    getch();
    
    curs_set(0);
}

void delete_entry(int row) {
    if (num_entries == 0) return;
    
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(num_entries + 6, 0, "DELETE ROW: %s | %s | %s | %s",
             entries[row].client,
             entries[row].server,
             entries[row].ip,
             entries[row].date);
    attroff(COLOR_PAIR(3) | A_BOLD);
    
    attron(COLOR_PAIR(2));
    mvprintw(num_entries + 7, 0, "Are you sure? (y/n): ");
    attroff(COLOR_PAIR(2));
    refresh();
    
    int ch = getch();
    if (ch != 'y' && ch != 'Y') {
        return;
    }
    
    for (int i = row; i < num_entries - 1; i++) {
        entries[i] = entries[i + 1];
    }
    num_entries--;
    
    save_file();
    
    attron(COLOR_PAIR(4));
    mvprintw(num_entries + 8, 0, "Row deleted! Press any key...");
    attroff(COLOR_PAIR(4));
    refresh();
    getch();
}

void edit_field(int row, int col) {
    char *field;
    int max_len;
    int is_secret = 0;
    
    if (col == 6) {
        attron(COLOR_PAIR(3));
        mvprintw(num_entries + 6, 0, "Expired column is calculated automatically. Press any key...");
        attroff(COLOR_PAIR(3));
        refresh();
        getch();
        return;
    }
    
    switch (col) {
        case 0: field = entries[row].client; max_len = 63; break;
        case 1: field = entries[row].server; max_len = 63; break;
        case 2: field = entries[row].secret; max_len = 63; is_secret = 1; break;
        case 3: field = entries[row].ip; max_len = 31; break;
        case 4: field = entries[row].date; max_len = 31; break;
        case 5: field = entries[row].months; max_len = 15; break;
        default: return;
    }
    
    char buffer[64];
    char confirm[64];
    int ch;
    
    curs_set(1);
    
    if (is_secret) {
        mvprintw(num_entries + 7, 0, "Enter: Confirm | Esc: Cancel");
        if (!get_input(buffer, max_len, num_entries + 6, 20, "Enter new password: ", 1)) {
            curs_set(0);
            return;
        }
        
        if (!get_input(confirm, max_len, num_entries + 8, 20, "Confirm password:   ", 1)) {
            curs_set(0);
            return;
        }
        
        if (strcmp(buffer, confirm) != 0) {
            attron(COLOR_PAIR(3));
            mvprintw(num_entries + 10, 0, "Passwords do not match! Press any key...");
            attroff(COLOR_PAIR(3));
            refresh();
            getch();
            curs_set(0);
            return;
        }
        
        strcpy(field, buffer);
        md5_hash(entries[row].secret, entries[row].secret_md5);
        save_file();
        
        attron(COLOR_PAIR(4));
        mvprintw(num_entries + 10, 0, "Password saved! Press any key...");
        attroff(COLOR_PAIR(4));
        refresh();
        getch();
        
    } else {
        strcpy(buffer, field);
        int pos = strlen(buffer);
        
        mvprintw(num_entries + 6, 0, "Editing: %-40s", buffer);
        mvprintw(num_entries + 7, 0, "Enter: Save | Esc: Cancel");
        refresh();
        
        while (1) {
            ch = getch();
            
            if (ch == 27) {
                break;
            } else if (ch == 10 || ch == KEY_ENTER) {
                if (strlen(buffer) > 0) {
                    strcpy(field, buffer);
                    if (col == 4 || col == 5) {
                        calculate_expired(&entries[row]);
                    }
                    save_file();
                }
                break;
            } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                if (pos > 0) {
                    buffer[--pos] = '\0';
                }
            } else if (pos < max_len && ch >= 32 && ch <= 126) {
                buffer[pos++] = ch;
                buffer[pos] = '\0';
            }
            
            mvprintw(num_entries + 6, 9, "%-40s", buffer);
            refresh();
        }
    }
    
    curs_set(0);
}

void remove_quotes(char *str) {
    int len = strlen(str);
    
    if (len >= 2 && str[0] == '"' && str[len-1] == '"') {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
    }
}

void draw_screen(int cur_row, int cur_col) {
    bkgd(COLOR_PAIR(1));
    clear();
    
    attron(A_BOLD | COLOR_PAIR(2));
    mvprintw(0, col_pos[0], "CLIENT");
    mvprintw(0, col_pos[1], "SERVER");
    mvprintw(0, col_pos[2], "SECRET (MD5)");
    mvprintw(0, col_pos[3], "IP");
    mvprintw(0, col_pos[4], "DATE");
    mvprintw(0, col_pos[5], "MONTHS");
    mvprintw(0, col_pos[6], "EXPIRED");
    attroff(A_BOLD | COLOR_PAIR(2));
    
    attron(COLOR_PAIR(1));
    mvhline(1, 0, '-', 100);
    attroff(COLOR_PAIR(1));
    
    for (int i = 0; i < num_entries; i++) {
        int row = i + 2;
        char *fields[] = {
            entries[i].client, entries[i].server, entries[i].secret_md5,
            entries[i].ip, entries[i].date, entries[i].months, entries[i].expired
        };
        for (int j = 0; j < NUM_COLS; j++) {
            // Determine color
            if (i == cur_row) {
                if (j == cur_col) {
                    attron(COLOR_PAIR(5) | A_BOLD);
                } else {
                    attron(COLOR_PAIR(6));
                }
            } else if (entries[i].is_expired) {
                // Entire row in red if expired
                attron(COLOR_PAIR(3));
            } else {
                attron(COLOR_PAIR(1));
            }
            
            mvprintw(row, col_pos[j], "%-*s", col_width[j], fields[j]);
            
            // Turn off color
            if (i == cur_row) {
                if (j == cur_col) {
                    attroff(COLOR_PAIR(5) | A_BOLD);
                } else {
                    attroff(COLOR_PAIR(6));
                }
            } else if (entries[i].is_expired) {
                attroff(COLOR_PAIR(3));
            } else {
                attroff(COLOR_PAIR(1));
            }
        }
    }
    
    attron(COLOR_PAIR(2));
    mvprintw(num_entries + 4, 0, "Arrow: Move | Enter: Edit | a: Add | d: Delete Row | q: Quit");
    attroff(COLOR_PAIR(2));
    
    refresh();
}

int main() {
    FILE *fp;
    char line[256];
    int line_num = 0, cur_row = 0, cur_col = 0, ch;
    
    fp = fopen(FILE_NAME, "r");
    if (fp == NULL) { printf("Cannot open file\n"); return 1; }
    
    while (fgets(line, sizeof(line), fp) && num_entries < MAX_ROWS) {
        line_num++;
        
        if (line_num <= 2) continue;
        
        int is_empty = 1;
        for (int i = 0; line[i]; i++) {
            if (line[i] != ' ' && line[i] != '\t' && line[i] != '\n' && line[i] != '\r') {
                is_empty = 0;
                break;
            }
        }
        if (is_empty) continue;
        if (line[0] == '#') continue;

        char *comment = strstr(line, "#0");
        if (!comment) comment = strstr(line, "#1");
        if (comment) {
            sscanf(comment, "#%s %s", entries[num_entries].date, entries[num_entries].months);
            *comment = '\0';
        }
        
        int parsed = sscanf(line, "%s %s %s %s", entries[num_entries].client, entries[num_entries].server,
               entries[num_entries].secret, entries[num_entries].ip);
        
        remove_quotes(entries[num_entries].secret);


        if (parsed < 4) continue;
        
        md5_hash(entries[num_entries].secret, entries[num_entries].secret_md5);
        calculate_expired(&entries[num_entries]);
        num_entries++;
    }
    fclose(fp);
    
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLUE);     // Normal text
    init_pair(2, COLOR_YELLOW, COLOR_BLUE);    // Header/footer
    init_pair(3, COLOR_RED, COLOR_BLUE);       // Expired row (red text on blue bg)
    init_pair(4, COLOR_GREEN, COLOR_BLUE);     // Success
    init_pair(5, COLOR_BLACK, COLOR_WHITE);    // Selected cell
    init_pair(6, COLOR_CYAN, COLOR_BLUE);      // Selected row
    
    draw_screen(cur_row, cur_col);
    
    while ((ch = getch()) != 'q') {
        switch (ch) {
            case KEY_UP:
                if (cur_row > 0) cur_row--;
                break;
            case KEY_DOWN:
                if (cur_row < num_entries - 1) cur_row++;
                break;
            case KEY_LEFT:
                if (cur_col > 0) cur_col--;
                break;
            case KEY_RIGHT:
                if (cur_col < NUM_COLS - 1) cur_col++;
                break;
            case 10:
            case KEY_ENTER:
                if (num_entries > 0) {
                    edit_field(cur_row, cur_col);
                }
                break;
            case 'a':
            case 'A':
                add_new_entry();
                break;
            case 'd':
            case 'D':
                if (num_entries > 0) {
                    delete_entry(cur_row);
                    if (cur_row >= num_entries && num_entries > 0) {
                        cur_row = num_entries - 1;
                    }
                }
                break;
        }
        draw_screen(cur_row, cur_col);
    }
    endwin();
    return 0;
}
