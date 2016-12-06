/* "Military-Grade Password Manager" - Hushcon 2015 CTF  */
/* Public domain 2015, epixoip@hushcon.com               */
/* cc -g -W -Wall -o passwd_mgr passwd_mgr.c             */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>

typedef struct {
    #define KEYLEN 256
    uint32_t state[KEYLEN];
} KEY;

typedef struct {
    #define BUFLEN 16
    uint32_t version;
    unsigned char master_pass[BUFLEN];
} HEADER;

typedef struct {
    unsigned char site[BUFLEN * 2];
    unsigned char user[BUFLEN];
    unsigned char pass[BUFLEN];
} ENTRY;

enum
{
    SITE,
    USER,
    PASS
};

char * const add_opts[] =
{
    [SITE] = "site",
    [USER] = "username",
    [PASS] = "password",
    NULL
};

static struct option longopts[] =
{
    { "help", no_argument,       0, 'h' },
    { "show", no_argument,       0, 's' },
    { "init", no_argument,       0, 'i' },
    { "add",  required_argument, 0, 'a' },
    { 0,      0,                 0,  0  }
};

void help()
{
    fprintf(stderr,
        "\nMilitary-Grade Password Manager\n"
        "Usage: ./passwd_mgr [options] [suboptions] <database>\n\n"
        "--init\n"
        "\tInitialize a new database.\n\n"
        "--show\n"
        "\tShow all passwords in a database.\n\n"
        "--add site=X,username=Y,password=Z\n"
        "\tAdd a password to the database.\n\n"
    );
}

void derive_key(KEY *key, unsigned char *pass, const size_t len)
{
    unsigned char buf[BUFLEN] = {0};
    size_t buflen = BUFLEN;
    uint32_t seed = 0;
    int i = 0;

    if (len < BUFLEN)
        buflen = len;

    memcpy(&buf, pass, buflen);

    for (; i < BUFLEN - 4; i+=4)
        seed ^= (uint32_t) buf[i+0] <<  0
              | (uint32_t) buf[i+1] <<  8
              | (uint32_t) buf[i+2] << 16
              | (uint32_t) buf[i+3] << 24;

    srand(seed);

    for (i = 0; i < KEYLEN; i++)
        key->state[i] = rand() & 0xffff;
}

void encrypt(KEY *key, unsigned char *data, const size_t len)
{
    uint32_t i = 0, t = 0, x = 0, y = 0;
    uint32_t state[KEYLEN];

    memcpy(&state, key->state, sizeof(state));

    for (; i < len; i++)
    {
        x = (x + 1) % KEYLEN;
        y = (y + state[x]) % KEYLEN;

        t = state[x];
        state[x] = state[y];
        state[y] = t;

        t = (state[x] + state[y]) % KEYLEN;
        data[i] = state[t] ^ data[i];
    }
}

int init(char *db)
{
    KEY key;
    HEADER hdr;
    FILE *dbh;

    if ((dbh = fopen(db, "w")) == NULL)
        return errno;

    #define VERSION 1297106765
    hdr.version = VERSION;

    while (1)
    {
        size_t len = BUFLEN;
        unsigned char *master, *verify;

        master = (unsigned char *) getpass("Select master password  : ");

        if (strlen((char *) master) < BUFLEN)
            len = strlen((char *) master);

        memset(&hdr.master_pass, 0, sizeof(hdr.master_pass));
        memcpy(&hdr.master_pass, master, len);

        verify = (unsigned char *) getpass("Confirm master password : ");

        if (strlen((char *) verify) == len &&
            memcmp(hdr.master_pass, verify, len) == 0
           ) break;

        printf("\nPasswords do not match!\n\n");
        sleep(1);
    }

    derive_key(&key, hdr.master_pass, BUFLEN);
    encrypt(&key, hdr.master_pass, BUFLEN);

    fwrite(&hdr, sizeof(hdr), 1, dbh);
    fclose(dbh);

    return 0;
}

int show(char *db)
{
    KEY key;
    HEADER hdr;
    ENTRY entry;
    FILE *dbh;
    int count = 0;

    if ((dbh = fopen(db, "r")) == NULL)
        return errno;

    fread(&hdr, sizeof(hdr), 1, dbh);

    while (1)
    {
        unsigned char *master = (unsigned char *) getpass("Enter master password : ");

        derive_key(&key, master, strlen((char *) master));
        encrypt(&key, hdr.master_pass, BUFLEN);

        if (strlen((char *) master) == strlen((char *) hdr.master_pass) &&
            memcmp(master, hdr.master_pass, strlen((char *) master)) == 0
           ) break;

        encrypt(&key, hdr.master_pass, BUFLEN);

        printf("\nIncorrect password!\n\n");
        sleep(1);

        if (++count == 3) return EACCES;
    }

    printf("\n%-32s\t%-16s\t%-16s\n", "SITE", "USERNAME", "PASSWORD");
    printf("--------------------------------");
    printf("--------------------------------");
    printf("----------------\n");

    while (!feof(dbh) && fread(&entry, sizeof(entry), 1, dbh) == 1)
    {
        encrypt(&key, entry.site, sizeof(entry.site));
        encrypt(&key, entry.user, sizeof(entry.user));
        encrypt(&key, entry.pass, sizeof(entry.pass));

        printf("%-32s\t%-16s\t%-16s\n", entry.site, entry.user, entry.pass);
    }

    printf ("\n");

    fclose(dbh);

    return 0;
}

int add(char *db, char *site, char *user, char *pass)
{
    KEY key;
    HEADER hdr;
    ENTRY entry;
    FILE *dbh;
    int count = 0;
    size_t len = BUFSIZ;

    if ((dbh = fopen(db, "r")) == NULL)
        return errno;

    fread(&hdr, sizeof(hdr), 1, dbh);
    fclose(dbh);

    while (1)
    {
        unsigned char *master = (unsigned char *) getpass("Enter master password : ");

        derive_key(&key, master, strlen((char *) master));
        encrypt(&key, hdr.master_pass, BUFLEN);

        if (strlen((char *) master) == strlen((char *) hdr.master_pass) &&
            memcmp(master, hdr.master_pass, strlen((char *) master)) == 0
           ) break;

        encrypt(&key, hdr.master_pass, BUFLEN);

        printf("\nIncorrect password!\n\n");
        sleep(1);

        if (++count == 3) return EACCES;
    }

    len = strlen(site);
    if (len > BUFLEN * 2 - 1)
        len = BUFLEN * 2 - 1;

    memset(&entry.site, 0, BUFLEN * 2);
    memcpy(&entry.site, site, len);

    encrypt(&key, entry.site, BUFLEN * 2);

    len = strlen(user);
    if (len > BUFLEN - 1)
        len = BUFLEN - 1;

    memset(&entry.user, 0, BUFLEN);
    memcpy(&entry.user, user, len);

    encrypt(&key, entry.user, BUFLEN);

    len = strlen(pass);
    if (len > BUFLEN - 1)
        len = BUFLEN - 1;

    memset(&entry.pass, 0, BUFLEN);
    memcpy(&entry.pass, pass, len);

    encrypt(&key, entry.pass, BUFLEN);

    if ((dbh = fopen(db, "a+")) == NULL)
        return errno;

    fwrite(&entry, sizeof(entry), 1, dbh);
    fclose(dbh);

    return 0;
}

int main(int argc, char **argv)
{
    char *db = NULL, *site = NULL, *user = NULL, *pass = NULL;
    char *subopt, *value;

    int opts = 0, idx = 0, ret = 0;
    int _init = 0, _show = 0, _add = 0;

    while (1)
    {
        if ((opts = getopt_long_only(argc, argv, "", longopts, &idx)) == -1)
            break;

        switch (opts)
        {
            case 0:

                if (longopts[idx].flag)
                    break;

            case 'h':

                help();
                return 0;

            case 'i':

                _init++;
                break;

            case 's':

                _show++;
                break;

            case 'a':

                _add++;
                subopt = optarg;

                while (*subopt != '\0')
                {
                    switch (getsubopt(&subopt, add_opts, &value))
                    {
                        case SITE:
                            site = strdup(value);
                            break;
                        case USER:
                            user = strdup(value);
                            break;
                        case PASS:
                            pass = strdup(value);
                            break;
                        default:
                            fprintf(stderr, "Error: unknown option\n");
                            return -1;
                    }
                }

                break;

            default:
                abort();
        }
    }

    if (optind == argc)
    {
        fprintf(stderr, "Error: database required\n");

        return -1;
    }

    assert(db = strdup(argv[optind]));

    if (_init)
    {
        if ((ret = init(db)) != 0)
            fprintf(stderr, "Error: %s\n", strerror(ret));

        return ret;
    }

    if (_show)
    {
        if ((ret = show(db)) != 0)
            fprintf(stderr, "Error: %s\n", strerror(ret));

        return ret;
    }

    if (_add)
    {
        assert(site != NULL);
        assert(user != NULL);
        assert(pass != NULL);

        if ((ret = add(db, site, user, pass)) != 0)
            fprintf(stderr, "Error: %s\n", strerror(ret));

        return ret;
    }

    return -1;
}
