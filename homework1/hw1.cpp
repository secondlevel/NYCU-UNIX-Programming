#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <filesystem>
#include <vector>
#include <regex>

#define MAX_LEN 20
#define NUM_FD 5
#define N_BITS 3

using namespace std;

typedef struct ps_info
{
    char command[MAX_LEN];
    int pid;
    char username[MAX_LEN];
    char fd[20];
    char type[MAX_LEN];
    int inode;
    char name[500];
} mps;

int check_number(char *);
int uid_to_username();
// type inode name
void stat_file_type();
void stat_inode();
void stat_fd_permission(char fd_number[], char fd_di[], mps *);
int check_file_permission();
void copy_ps_information(mps *, mps *);
bool compare_information(vector<mps *>, mps *);
void show_single(mps *);
void filter_content(vector<mps *>, int c_flag_filter, int t_flag_filter, int f_flag_filter, char c_filter[], char t_filter[], char f_filter[]);
void remove_redundant(vector<mps *>, vector<mps *>);

int check_number(char p_name[])
{
    long unsigned int i, len;
    len = strlen(p_name);
    if (len == 0)
        return -1;
    for (i = 0; i < len; i++)
        if (p_name[i] < '0' || p_name[i] > '9')
            return -1;
    return 0;
}

int check_file_permission(char file_dir[], char file_name[])
{
    chdir(file_dir);
    errno = 0;
    struct stat file_info;
    if (stat(file_name, &file_info) == -1)
    {
        switch (errno)
        {
        case EACCES:
            return 1;
            break;
        case ENOENT:
            return 2;
            break;
        case ENOTDIR:
            return 3;
            break;
        case EFAULT:
            return 4;
            break;
        case ENOMEM:
            return 5;
            break;
        case ENAMETOOLONG:
            return 6;
            break;
        }
    }
    else
        return 0;
}

int uid_to_username(uid_t uid, struct ps_info *p1) //由uid得到username
{
    struct passwd *pw_ptr;
    static char numstr[10];

    if ((pw_ptr = getpwuid(uid)) == NULL)
    {
        sprintf(numstr, "%d", uid);
        strcpy(p1->username, numstr);
    }
    else
    {
        strcpy(p1->username, pw_ptr->pw_name);
    }
    return 0;
}

void stat_file_type(struct stat ps_buffer, struct ps_info *p1) // file type
{
    static char file_type[20];

    // file type
    switch (ps_buffer.st_mode & S_IFMT)
    {
    case S_IFCHR:
        strcpy(p1->type, "CHR");
        break;
    case S_IFDIR:
        strcpy(p1->type, "DIR");
        break;
    case S_IFIFO:
        strcpy(p1->type, "FIFO");
        break;
    case S_IFREG:
        strcpy(p1->type, "REG");
        break;
    case S_IFSOCK:
        strcpy(p1->type, "SOCK");
        break;
    default:
        strcpy(p1->type, "unknown");
        break;
    }
}

void stat_fd_permission(char fd_number[20], char fd_di[255], mps *fd_mps)
{
    unsigned int i, mask = 0700;
    struct stat buff;
    static char *perm[] = {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};
    char fd_permission[1];
    if ((lstat(fd_di, &buff) != -1))
    {
        if (strstr(perm[(buff.st_mode & mask) >> (3 - 1) * N_BITS], "rw"))
        {
            strcpy(fd_permission, "u");
            mask >>= N_BITS;
        }
        else if (strstr(perm[(buff.st_mode & mask) >> (3 - 1) * N_BITS], "w"))
        {
            strcpy(fd_permission, "w");
            mask >>= N_BITS;
        }
        else if (strstr(perm[(buff.st_mode & mask) >> (3 - 1) * N_BITS], "r"))
        {
            strcpy(fd_permission, "r");
            mask >>= N_BITS;
        }
    }
    sprintf(fd_mps->fd, "%s%s", fd_number, fd_permission);
}

void stat_inode(struct stat ps_buffer, struct ps_info *p1)
{
    p1->inode = ps_buffer.st_ino;
}

void copy_ps_information(mps *origin, mps *after)
{
    sprintf(after->command, "%s", origin->command);
    sprintf(after->username, "%s", origin->username);
    sprintf(after->fd, "%s", origin->fd);
    sprintf(after->type, "%s", origin->type);
    sprintf(after->name, "%s", origin->name);
    after->pid = origin->pid;
    after->inode = origin->inode;
}

bool compare_information(vector<mps *> total, mps *first)
{
    int flag = 0;
    for (auto second : total)
    {
        char pid_char1[20], inode_char1[20], pid_char2[20], inode_char2[20];
        string compare1 = "";
        compare1 += string(first->command);

        sprintf(pid_char1, "%d", first->pid);

        compare1 += string(pid_char1);
        compare1 += string(first->username);
        compare1 += string(first->fd);
        compare1 += string(first->type);

        sprintf(inode_char1, "%d", first->inode);

        compare1 += string(inode_char1);
        compare1 += string(first->name);

        string compare2 = "";
        compare2 += string(second->command);

        sprintf(pid_char2, "%d", second->pid);

        compare2 += string(pid_char2);
        compare2 += string(second->username);
        compare2 += string(second->fd);
        compare2 += string(second->type);

        sprintf(inode_char2, "%d", second->inode);

        compare2 += string(inode_char2);
        compare2 += string(second->name);

        compare1.erase(std::remove(compare1.begin(), compare1.end(), ' '), compare1.end());
        compare2.erase(std::remove(compare2.begin(), compare2.end(), ' '), compare2.end());

        if ((strcmp(first->fd, "mem") == 0 && strcmp(second->fd, "txt") == 0) || (strcmp(first->fd, "mem") == 0 && strcmp(second->fd, "cwd") == 0) || (strcmp(first->fd, "mem") == 0 && strcmp(second->fd, "rtd") == 0))
        {
            flag = 0;
            if (strcmp(first->command, second->command) == 0)
                flag += 1;
            if (first->pid == second->pid)
                flag += 1;
            if (strcmp(first->username, second->username) == 0)
                flag += 1;
            if (strcmp(first->type, second->type) == 0)
                flag += 1;
            if (first->inode == second->inode)
                flag += 1;
            if (strcmp(first->name, second->name) == 0)
                flag += 1;
            if (flag == 6)
                return false;
        }

        if (strcmp(compare1.c_str(), compare2.c_str()) == 0)
            return false;
    }
    return true;
}

void show_single(mps *single)
{
    printf("%s\t\t%d\t%s\t%s\t%s\t%d\t%s\n", single->command, single->pid, single->username, single->fd, single->type, single->inode, single->name);
}

void show_all(vector<mps *> total)
{
    for (auto current : total)
    {
        if (current->inode == 123456789)
            printf("%s\t\t%d\t%s\t%s\t%s\t%s\t%s\n", current->command, current->pid, current->username, current->fd, current->type, " ", current->name);
        else
            printf("%s\t\t%d\t%s\t%s\t%s\t%d\t%s\n", current->command, current->pid, current->username, current->fd, current->type, current->inode, current->name);
    }
}

void filter_content(vector<mps *> total, int c_flag_filter, int t_flag_filter, int f_flag_filter, char c_filter[100], char t_filter[100], char f_filter[100])
{
    for (auto disallow : total)
    {
        int c_allow = 0, t_allow = 0, f_allow = 0;
        if (c_flag_filter)
        {
            regex regc(c_filter);
            if (regex_search(disallow->command, regc))
            {
                c_allow = 1;
            }
        }
        else
            c_allow = 1;

        if (t_flag_filter)
        {
            regex regt(t_filter);
            if (regex_search(disallow->type, regt))
            {
                t_allow = 1;
            }
        }
        else
            t_allow = 1;

        if (f_flag_filter)
        {
            regex regf(f_filter);
            if (regex_search(disallow->name, regf))
            {
                f_allow = 1;
            }
        }
        else
            f_allow = 1;

        if (c_allow && t_allow && f_allow)
            show_single(disallow);
    }
}
void remove_redundant(vector<mps *> total, vector<mps *> after)
{
    for (auto old_mps : total)
    {
        bool add = true;
        for (auto new_mps : after)
        {
            // int clean = 0;

            // if (strcmp(old_mps->command, new_mps->command) == 0)
            //     clean += 1;
            // if (old_mps->pid == new_mps->pid)
            //     clean += 1;
            // if (strcmp(old_mps->username, new_mps->username) == 0)
            //     clean += 1;
            // if (strcmp(old_mps->fd, new_mps->fd) == 0)
            //     clean += 1;
            // if (strcmp(old_mps->type, new_mps->type) == 0)
            //     clean += 1;
            // if (old_mps->inode == new_mps->inode)
            //     clean += 1;
            // if (strcmp(old_mps->name, new_mps->name) == 0)
            //     clean += 1;

            // if (clean == 7)
            // {
            //     add = false;
            //     break;
            // }

            char pid_char1[20], inode_char1[20], pid_char2[20], inode_char2[20];
            string compare1 = "";
            compare1 += string(old_mps->command);

            sprintf(pid_char1, "%d", old_mps->pid);

            compare1 += string(pid_char1);
            compare1 += string(old_mps->username);
            compare1 += string(old_mps->fd);
            compare1 += string(old_mps->type);

            sprintf(inode_char1, "%d", old_mps->inode);

            compare1 += string(inode_char1);
            compare1 += string(old_mps->name);

            string compare2 = "";
            compare2 += string(new_mps->command);

            sprintf(pid_char2, "%d", new_mps->pid);

            compare2 += string(pid_char2);
            compare2 += string(new_mps->username);
            compare2 += string(new_mps->fd);
            compare2 += string(new_mps->type);

            sprintf(inode_char2, "%d", new_mps->inode);

            compare2 += string(inode_char2);
            compare2 += string(new_mps->name);

            compare1.erase(std::remove(compare1.begin(), compare1.end(), ' '), compare1.end());
            compare2.erase(std::remove(compare2.begin(), compare2.end(), ' '), compare2.end());

            if (strcmp(compare1.c_str(), compare2.c_str()) == 0)
            {
                add = false;
                break;
            }
        }
        if (add)
        {
            mps *transfer = (struct ps_info *)malloc(sizeof(struct ps_info));
            copy_ps_information(old_mps, transfer);
            after.push_back(transfer);
        }
    }
}
int main(int argc, char *argv[])
{
    DIR *dir_ptr;
    mps *ps_list;
    struct dirent *direntp;
    struct stat infobuf;
    vector<mps *> total_mps;
    vector<mps *> clear_mps;

    int opt;
    int c_flag = 0, t_flag = 0, f_flag = 0;
    char *opt_string = "c::t::f::";
    char option_c[100], option_t[100], option_f[100];

    while ((opt = getopt(argc, argv, opt_string)) != -1)
    {
        switch (opt)
        {
        case 'c':
            sprintf(option_c, "%s", argv[optind]);
            c_flag = 1;
            break;
        case 't':
            sprintf(option_t, "%s", argv[optind]);
            t_flag = 1;
            break;
        case 'f':
            sprintf(option_f, "%s", argv[optind]);
            f_flag = 1;
            break;
        }
    }

    if (t_flag)
        if (strcmp(option_t, "REG") != 0 && strcmp(option_t, "CHR") && strcmp(option_t, "DIR") && strcmp(option_t, "FIFO") && strcmp(option_t, "SOCK") && strcmp(option_t, "unknown"))
        {
            printf("%s\n", "Invalid TYPE option");
            exit(0);
        }

    if ((dir_ptr = opendir("/proc")) != NULL)
    {
        printf("COMMAND\t\tPID\tUSER\tFD\tTYPE\tNODE\tNAME\n");
        while ((direntp = readdir(dir_ptr)) != NULL) //遍歷/proc所有目錄
        {
            if ((check_number(direntp->d_name)) == 0) //判斷目錄是不是數字
            {

                FILE *fd, *fd_check, *map_file;
                char dir[20];
                char pid_name[10];

                char *FD_CAT[] = {"cwd",
                                  "root",
                                  "exe",
                                  "maps",
                                  "fd"};

                char *FD_DISPLAY_CAT[] = {"cwd",
                                          "rtd",
                                          "txt",
                                          "mem",
                                          "fd"};

                strcpy(pid_name, direntp->d_name);

                sprintf(dir, "%s/%s/", "/proc", pid_name);

                for (int i = 0; i < NUM_FD; i++)
                {
                    ps_list = (struct ps_info *)malloc(sizeof(struct ps_info));

                    // find username
                    chdir("/proc");                     //切換至proc/目錄
                    if (stat(pid_name, &infobuf) == -1) // get process USER
                        break;
                    else
                        uid_to_username(infobuf.st_uid, ps_list);

                    // find command, pid
                    chdir(dir); //切換至proc/pid目錄
                    if ((fd = fopen("stat", "r")) < 0)
                        break;
                    while (1 == fscanf(fd, "%d\n", &(ps_list->pid)))
                        break;

                    fclose(fd);

                    if ((fd = fopen("comm", "r")) < 0)
                        break;
                    while (1 == fscanf(fd, "%s\n", ps_list->command))
                        break;

                    fclose(fd);

                    int permission_number, dir_permission;

                    permission_number = check_file_permission(dir, FD_CAT[i]);

                    errno = 0;
                    if (permission_number == 0)
                    {
                        if ((access(FD_CAT[i], 4) == -1 && errno == 13) || fopen(FD_CAT[i], "r") < 0)
                            permission_number = 1;
                    }

                    if (errno == 13)
                        permission_number = 1;

                    if (permission_number > 1)
                        break;

                    else if (permission_number == 1)
                    {
                        char permission[30];
                        strcpy(ps_list->type, "unknown");
                        if (strcmp(FD_CAT[i], "fd") == 0)
                        {
                            strcpy(ps_list->fd, "NOFD");
                            strcpy(ps_list->type, " ");
                        }
                        else
                            strcpy(ps_list->fd, FD_DISPLAY_CAT[i]);

                        sprintf(permission, "%s", " (Permission denied)");
                        sprintf(ps_list->name, "%s/%s %s", dir, FD_CAT[i], permission);
                        ps_list->inode = 123456789;

                        mps *stor_ps1 = (struct ps_info *)malloc(sizeof(struct ps_info));
                        copy_ps_information(ps_list, stor_ps1);
                        if (compare_information(total_mps, stor_ps1))
                            total_mps.push_back(stor_ps1);
                        else
                            free(stor_ps1);

                        // printf("%s\t\t%d\t%s\t%s\t%s\t%s\t%s\n", ps_list->command, ps_list->pid, ps_list->username, ps_list->fd, ps_list->type, " ", ps_list->name);
                    }
                    else if (permission_number == 0)
                    {
                        if (strcmp(FD_CAT[i], "cwd") == 0 || strcmp(FD_CAT[i], "root") == 0 || strcmp(FD_CAT[i], "exe") == 0)
                        {
                            chdir(dir);
                            char fd_file[50];
                            struct stat infobuf;
                            // type inode name
                            // stat(FD_CAT[i], &infobuf);
                            sprintf(fd_file, "%s/%s", dir, FD_CAT[i]);
                            if (stat(FD_CAT[i], &infobuf) == -1) // get process USER
                                break;
                            else
                            {
                                stat_file_type(infobuf, ps_list);
                                stat_inode(infobuf, ps_list);
                            }

                            // name
                            string file_dir(fd_file);
                            string name;
                            auto link = std::filesystem::path(fd_file);
                            name = std::filesystem::read_symlink(link);
                            sprintf(ps_list->name, "%s", name.c_str());

                            // fd
                            strcpy(ps_list->fd, FD_DISPLAY_CAT[i]);

                            mps *stor_ps2 = (struct ps_info *)malloc(sizeof(struct ps_info));
                            copy_ps_information(ps_list, stor_ps2);
                            if (compare_information(total_mps, stor_ps2))
                                total_mps.push_back(stor_ps2);
                            else
                                free(stor_ps2);

                            // printf("%s\t\t%d\t%s\t%s\t%s\t%d\t%s\n", ps_list->command, ps_list->pid, ps_list->username, ps_list->fd, ps_list->type, ps_list->inode, ps_list->name);
                        }
                        else if (strcmp(FD_CAT[i], "maps") == 0)
                        {
                            chdir(dir);
                            struct stat infobuf2;
                            FILE *map_fd;
                            char StrLine[1024];

                            // stat maps txt file
                            if (stat("maps", &infobuf2) == -1)
                                break;
                            else
                                stat_file_type(infobuf2, ps_list);

                            if ((map_fd = fopen("maps", "r")) < 0)
                                continue;

                            while (!feof(map_fd))
                            {
                                // fd
                                strcpy(ps_list->fd, FD_DISPLAY_CAT[i]);

                                fgets(StrLine, 1024, map_fd); //讀取一行

                                if (strstr(StrLine, "(deleted)"))
                                    sprintf(ps_list->fd, "%s", "DEL");

                                // 設置切割字符
                                const char *delim = " ";
                                int map_cnt = 0, stor_inode = 0;

                                // 切割字串
                                for (char *pch = strtok(StrLine, delim); pch; pch = strtok(NULL, delim))
                                {
                                    // inode
                                    if (map_cnt == 4)
                                    {
                                        if (strcmp(pch, "0") == 0)
                                            stor_inode = 1;
                                        else
                                            ps_list->inode = atoi(pch);
                                    }

                                    // name
                                    if (map_cnt == 5 && stor_inode != 1)
                                    {
                                        string map_name(pch);
                                        int map_index = map_name.find("\n", 0);
                                        if (map_index != -1)
                                            map_name.erase(map_index);
                                        strcpy(ps_list->name, map_name.c_str());
                                    }
                                    map_cnt += 1;
                                }

                                mps *stor_ps3 = (struct ps_info *)malloc(sizeof(struct ps_info));
                                copy_ps_information(ps_list, stor_ps3);
                                if (compare_information(total_mps, stor_ps3))
                                    total_mps.push_back(stor_ps3);
                                else
                                    free(stor_ps3);

                                // printf("%s\t\t%d\t%s\t%s\t%s\t%d\t%s\n", ps_list->command, ps_list->pid, ps_list->username, ps_list->fd, ps_list->type, ps_list->inode, ps_list->name);
                            }
                            fclose(map_fd);
                        }
                        else if (strcmp(FD_CAT[i], "fd") == 0)
                        {
                            DIR *dir_fd_ptr;
                            struct dirent *fd_direntp;
                            struct stat infobuf3;
                            char fd_dirname[255];

                            // fd type inode name
                            chdir(dir);
                            if ((dir_fd_ptr = opendir("fd")) != NULL)
                            {
                                while ((fd_direntp = readdir(dir_fd_ptr)) != NULL) //遍歷/proc/pid/fd所有目錄
                                {
                                    if (check_number(fd_direntp->d_name) == 0)
                                    {
                                        sprintf(fd_dirname, "%s/%s", "fd", fd_direntp->d_name);

                                        // stat fd directory
                                        if (stat(fd_dirname, &infobuf3) == -1)
                                            continue;
                                        else
                                        {
                                            // fd
                                            char fdfd[20];
                                            sprintf(fdfd, "%s", fd_direntp->d_name);
                                            stat_fd_permission(fdfd, fd_dirname, ps_list);

                                            // type
                                            stat_file_type(infobuf3, ps_list);

                                            // inode
                                            ps_list->inode = infobuf3.st_ino;

                                            // name
                                            string fd_file_dir(fd_dirname);
                                            string fd_name;
                                            auto fd_link = std::filesystem::path(fd_file_dir);
                                            fd_name = std::filesystem::read_symlink(fd_link);
                                            if (strstr(fd_name.c_str(), "(deleted)"))
                                                fd_name = fd_name.replace(fd_name.end() - 9, fd_name.end(), "");
                                            sprintf(ps_list->name, "%s", fd_name.c_str());

                                            mps *stor_ps4 = (struct ps_info *)malloc(sizeof(struct ps_info));
                                            copy_ps_information(ps_list, stor_ps4);
                                            if (compare_information(total_mps, stor_ps4))
                                                total_mps.push_back(stor_ps4);
                                            else
                                                free(stor_ps4);

                                            // printf("%s\t\t%d\t%s\t%s\t%s\t%d\t%s\n", ps_list->command, ps_list->pid, ps_list->username, ps_list->fd, ps_list->type, ps_list->inode, ps_list->name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    free(ps_list);
                }
            }
        }
    }
    closedir(dir_ptr);
    remove_redundant(total_mps, clear_mps);
    filter_content(total_mps, c_flag, t_flag, f_flag, option_c, option_t, option_f);
    for (mps *current : total_mps)
        free(current);
    for (mps *current : clear_mps)
        free(current);
    total_mps.clear();
    clear_mps.clear();

    return 0;
}