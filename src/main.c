/** @file main.c
 * @brief CLI entry point: argument dispatch, password prompt, real-time display.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>

#include "base32.h"
#include "totp.h"
#include "vault.h"
#include "memzero.h"

static volatile sig_atomic_t show_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    show_running = 0;
}

static void read_password(const char *prompt, char *buf, size_t buf_size)
{
    int tty = isatty(fileno(stdin));
    struct termios old;

    if (tty)
    {
        struct termios new;
        tcgetattr(fileno(stdin), &old);
        new = old;
        new.c_lflag &= ~(ECHO);
        tcsetattr(fileno(stdin), TCSANOW, &new);
    }

    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)buf_size, stdin))
        buf[strcspn(buf, "\n")] = '\0';

    if (tty)
    {
        tcsetattr(fileno(stdin), TCSANOW, &old);
        printf("\n");
    }
}

static void print_usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  cauth init                   Create a new encrypted vault\n"
        "  cauth add <issuer> <account> <secret>   Add an account\n"
        "  cauth list                   List all accounts\n"
        "  cauth show [--once] <issuer> <account>  Show TOTP (realtime, or --once for one-shot)\n"
        "  cauth remove <issuer> <account>         Remove an account\n");
}

static int cmd_init(void)
{
    char pw1[256], pw2[256];
    read_password("Master Password: ", pw1, sizeof(pw1));
    read_password("Confirm: ", pw2, sizeof(pw2));

    if (strcmp(pw1, pw2) != 0)
    {
        fprintf(stderr, "Error: passwords do not match\n");
        memzero(pw1, sizeof(pw1));
        memzero(pw2, sizeof(pw2));
        return 1;
    }

    Vault vault;
    vault_init(&vault);
    int ret = vault_save(&vault, pw1);

    memzero(pw1, sizeof(pw1));
    memzero(pw2, sizeof(pw2));
    vault_free(&vault);

    if (ret != 0)
    {
        fprintf(stderr, "Error: failed to create vault\n");
        return 1;
    }

    printf("Vault created successfully\n");
    return 0;
}

static int cmd_add(int argc, char **argv)
{
    if (argc < 5)
    {
        fprintf(stderr, "Usage: cauth add <issuer> <account> <secret>\n");
        return 1;
    }

    char pw[256];
    read_password("Master Password: ", pw, sizeof(pw));

    Vault vault;
    vault_init(&vault);
    if (vault_load(&vault, pw) != 0)
    {
        fprintf(stderr, "Error: failed to load vault (wrong password?)\n");
        memzero(pw, sizeof(pw));
        return 1;
    }

    if (vault_add(&vault, argv[2], argv[3], argv[4]) != 0)
    {
        fprintf(stderr, "Error: account already exists or invalid\n");
        memzero(pw, sizeof(pw));
        vault_free(&vault);
        return 1;
    }

    if (vault_save(&vault, pw) != 0)
    {
        fprintf(stderr, "Error: failed to save vault\n");
        memzero(pw, sizeof(pw));
        vault_free(&vault);
        return 1;
    }

    memzero(pw, sizeof(pw));
    vault_free(&vault);
    printf("Account added\n");
    return 0;
}

static int cmd_list(void)
{
    char pw[256];
    read_password("Master Password: ", pw, sizeof(pw));

    Vault vault;
    vault_init(&vault);
    if (vault_load(&vault, pw) != 0)
    {
        fprintf(stderr, "Error: failed to load vault (wrong password?)\n");
        memzero(pw, sizeof(pw));
        return 1;
    }

    memzero(pw, sizeof(pw));

    if (vault.count == 0)
    {
        printf("No accounts found\n");
    }
    else
    {
        printf("%-20s %-20s\n", "Issuer", "Account");
        printf("%-20s %-20s\n", "------", "-------");
        for (size_t i = 0; i < vault.count; i++)
            printf("%-20s %-20s\n",
                   vault.entries[i].issuer,
                   vault.entries[i].account);
    }

    vault_free(&vault);
    return 0;
}

static int cmd_show(int argc, char **argv)
{
    int once = 0;
    int issuer_idx = 2;

    if (argc > 2 && strcmp(argv[2], "--once") == 0)
    {
        once = 1;
        issuer_idx = 3;
    }

    if (argc < issuer_idx + 2)
    {
        fprintf(stderr, "Usage: cauth show [--once] <issuer> <account>\n");
        return 1;
    }

    char pw[256];
    read_password("Master Password: ", pw, sizeof(pw));

    Vault vault;
    vault_init(&vault);
    if (vault_load(&vault, pw) != 0)
    {
        fprintf(stderr, "Error: failed to load vault (wrong password?)\n");
        memzero(pw, sizeof(pw));
        return 1;
    }

    memzero(pw, sizeof(pw));

    VaultEntry *entry = vault_find(&vault, argv[issuer_idx], argv[issuer_idx + 1]);
    if (!entry)
    {
        fprintf(stderr, "Error: account not found\n");
        vault_free(&vault);
        return 1;
    }

    uint8_t secret[64];
    int secret_len = base32_decode(entry->secret, secret, sizeof(secret));
    if (secret_len < 0)
    {
        fprintf(stderr, "Error: invalid secret in vault\n");
        vault_free(&vault);
        return 1;
    }

    if (!once && isatty(fileno(stdout)))
    {
        signal(SIGINT, handle_sigint);

        while (show_running)
        {
            uint64_t now = (uint64_t)time(NULL);
            uint32_t token = totp_generate(secret, (size_t)secret_len, now);

            uint64_t elapsed = now % TOTP_TIME_STEP;
            uint64_t remaining = TOTP_TIME_STEP - elapsed;

            int bar_width = 20;
            int filled = (int)(remaining * bar_width / TOTP_TIME_STEP);

            printf("\r%06u  [", token);
            for (int i = 0; i < bar_width; i++)
                putchar(i < filled ? '#' : ' ');
            printf("]  %lus  ", (unsigned long)remaining);
            fflush(stdout);

            sleep(1);
        }

        printf("\n");
    }
    else
    {
        uint64_t now = (uint64_t)time(NULL);
        uint32_t token = totp_generate(secret, (size_t)secret_len, now);
        uint64_t remaining = TOTP_TIME_STEP - (now % TOTP_TIME_STEP);
        printf("%06u  (%lus left)\n", token, (unsigned long)remaining);
    }

    memzero(secret, sizeof(secret));
    vault_free(&vault);
    return 0;
}

static int cmd_remove(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: cauth remove <issuer> <account>\n");
        return 1;
    }

    char pw[256];
    read_password("Master Password: ", pw, sizeof(pw));

    Vault vault;
    vault_init(&vault);
    if (vault_load(&vault, pw) != 0)
    {
        fprintf(stderr, "Error: failed to load vault (wrong password?)\n");
        memzero(pw, sizeof(pw));
        return 1;
    }

    if (vault_remove(&vault, argv[2], argv[3]) != 0)
    {
        fprintf(stderr, "Error: account not found\n");
        memzero(pw, sizeof(pw));
        vault_free(&vault);
        return 1;
    }

    if (vault_save(&vault, pw) != 0)
    {
        fprintf(stderr, "Error: failed to save vault\n");
        memzero(pw, sizeof(pw));
        vault_free(&vault);
        return 1;
    }

    memzero(pw, sizeof(pw));
    vault_free(&vault);
    printf("Account removed\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "init") == 0)
        return cmd_init();
    else if (strcmp(argv[1], "add") == 0)
        return cmd_add(argc, argv);
    else if (strcmp(argv[1], "list") == 0)
        return cmd_list();
    else if (strcmp(argv[1], "show") == 0)
        return cmd_show(argc, argv);
    else if (strcmp(argv[1], "remove") == 0)
        return cmd_remove(argc, argv);
    else
    {
        print_usage();
        return 1;
    }
}
