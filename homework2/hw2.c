#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

// setenv("fd_content", 121, 0);

// int chmod(const char *pathname, mode_t mode);
static int (*old_chmod)(const char *, mode_t);

// int chown(const char *pathname, uid_t owner, gid_t group);
static int (*old_chown)(const char *, uid_t, gid_t);

// int close(int fd);
static int (*old_close)(int);

// int creat(const char *pathname, mode_t mode);
static int (*old_creat)(const char *, mode_t);

// int fclose(FILE *stream);
static int (*old_fclose)(FILE *);

// FILE *fopen(const char *pathname, const char *mode);
static FILE *(*old_fopen)(const char *, const char *);

// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*old_fread)(void *, size_t, size_t, FILE *);

// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*old_fwrite)(const void *, size_t, size_t, FILE *);

// int open(const char *pathname, int flags);
static int (*old_open)(const char *, int, ...);

// ssize_t read(int fd, void *buf, size_t count);
static ssize_t (*old_read)(int, void *, size_t);

// int remove(const char *pathname);
static int (*old_remove)(const char *);

// int rename(const char *oldpath, const char *newpath);
static int (*old_rename)(const char *, const char *);

// FILE *tmpfile(void);
static FILE *(*old_tmpfile)(void);

// ssize_t write(int fd, const void *buf, size_t count);
static ssize_t (*old_write)(int, const void *, size_t);

// decimal to octal
int dec2oct(int decimal);

int dec2oct(int decimal)
{
    int octal = 0, i = 1;

    while (decimal != 0)
    {
        octal += (decimal % 8) * i;
        decimal /= 8;
        i *= 10;
    }

    return octal;
}

int chmod(const char *pathname, mode_t mode)
{
    char realfilepath[1024];
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_chmod = dlsym(handle, "chmod");
    }

    int old_return = old_chmod(pathname, mode);

    realpath(pathname, realfilepath);

    // fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", realfilepath, mode, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] chmod(\"%s\", %o) = %d\n", realfilepath, mode, old_return);
    // printf("[logger] chmod(\"%s\", %o) = %d\n", realfilepath, mode, old_return);

    return old_return;
}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    char realfilepath[1024];
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_chown = dlsym(handle, "chown");
    }

    int old_return = old_chown(pathname, owner, group);
    realpath(pathname, realfilepath);

    // fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", realfilepath, owner, group, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] chown(\"%s\", %d, %d) = %d\n", realfilepath, owner, group, old_return);
    // dprintf(121, "[logger] chown(\"%s\", %d, %d) = %d\n", realfilepath, owner, group, old_return);
    // printf("[logger] chown(\"%s\", %d, %d) = %d\n", realfilepath, owner, group, old_return);

    return old_return;
}

int close(int fd)
{
    char filename[1024] = "";
    char filename_buf[1024] = "";

    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_close = dlsym(handle, "close");
    }

    snprintf(filename, 1024, "/proc/%ld/fd/%d", (long)getpid(), fd);

    readlink(filename, filename_buf, 1024);

    char filePath[1024];

    int old_return = old_close(fd);

    // fprintf(stderr, "[logger] close(\"%s\") = %d\n", filename_buf, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] close(\"%s\") = %d\n", filename_buf, old_return);
    // dprintf(121, "[logger] close(\"%s\") = %d\n", filename_buf, old_return);
    // printf("[logger] close(\"%s\") = %d\n", filename_buf, old_return);

    return old_return;
}

int creat(const char *pathname, mode_t mode)
{

    char realfilepath[1024];
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_creat = dlsym(handle, "creat");
    }

    int old_return = old_creat(pathname, mode);
    realpath(pathname, realfilepath);

    if (old_return == 2)
    {
        stdout = fdopen(old_return, "w");
    }

    // fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", realfilepath, mode, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] creat(\"%s\", %o) = %d\n", realfilepath, mode, old_return);
    // dprintf(121, "[logger] creat(\"%s\", %o) = %d\n", realfilepath, mode, old_return);
    // printf("[logger] creat(\"%s\", %o) = %d\n", realfilepath, mode, old_return);

    return old_return;
}

int fclose(FILE *stream)
{
    char filename[1024] = "";
    char filename_buf[1024] = "";
    struct stat *fclose_buf;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    int old_return;

    if (handle != NULL)
    {
        old_fclose = dlsym(handle, "fclose");
    }

    int fd = fileno(stream);
    int fd2;

    snprintf(filename, 1024, "/proc/%ld/fd/%d", (long)getpid(), fd);
    readlink(filename, filename_buf, 1024);

    if (fd == 2)
    {
        fd2 = dup(fd);
        FILE *tmp = fdopen(fd2, "w");
        old_return = old_fclose(stream);
    }
    else
    {
        old_return = old_fclose(stream);
    }

    // printf("close number %d\n", fd2);
    // fprintf(stderr, "[logger] fclose(\"%s\") = %d\n", filename_buf, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] fclose(\"%s\") = %d\n", filename_buf, old_return);
    // dprintf(121, "[logger] fclose(\"%s\") = %d\n", filename_buf, old_return);
    // printf("[logger] fclose(\"%s\") = %d\n", filename_buf, old_return);

    return old_return;
}

FILE *fopen(const char *pathname, const char *mode)
{
    FILE *old_return;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_fopen = dlsym(handle, "fopen");
    }

    old_return = old_fopen(pathname, mode);

    int fd = fileno(old_return);

    // fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, old_return);
    // dprintf(121, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, old_return);
    // printf("[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, old_return);

    return old_return;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    int index;
    char filename[1024] = "";
    char filename_buf[1024] = "";
    struct stat fstat_buf;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_fread = dlsym(handle, "fread");
    }

    int fd = fileno(stream);

    snprintf(filename, 1024, "/proc/%ld/fd/%d", (long)getpid(), fd);

    size_t old_return = old_fread(ptr, size, nmemb, stream);

    readlink(filename, filename_buf, 1024);

    char *buffer_content = (char *)ptr;

    int length;
    if ((int)old_return > 32)
        length = 32;
    else
        length = (int)old_return;

    char new_buffer_content[length + 1];
    new_buffer_content[length] = '\0';
    // memset(new_buffer_content, '\0', length + 1);

    for (index = 0; index < length; index++)
    {
        if (isprint(buffer_content[index]) == 0)
            new_buffer_content[index] = '.';
        else
            new_buffer_content[index] = buffer_content[index];
    }

    // fprintf(stderr, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", new_buffer_content, size, nmemb, filename_buf, old_return);
    dprintf(atoi(getenv("fd_content")), "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", new_buffer_content, size, nmemb, filename_buf, old_return);
    // dprintf(121, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)ptr, size, nmemb, filename_buf, old_return);
    // printf("[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)ptr, size, nmemb, filename_buf, old_return);

    return old_return;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    int index;
    char filename[1024] = "";
    char filename_buf[1024] = "";
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_fwrite = dlsym(handle, "fwrite");
    }

    size_t old_return = old_fwrite(ptr, size, nmemb, stream);
    int fd = fileno(stream);

    snprintf(filename, 1024, "/proc/%ld/fd/%d", (long)getpid(), fd);

    char *buffer_content = (char *)ptr;

    int length;
    if ((int)old_return > 32)
        length = 32;
    else
        length = (int)old_return;

    char new_buffer_content[length + 1];
    new_buffer_content[length] = '\0';
    // memset(new_buffer_content, '\0', length + 1);

    for (index = 0; index < length; index++)
    {
        if (isprint(buffer_content[index]) == 0)
            new_buffer_content[index] = '.';
        else
            new_buffer_content[index] = buffer_content[index];
    }

    if (readlink(filename, filename_buf, 1024) > 0)
    {
        // fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", new_buffer_content, size, nmemb, filename_buf, old_return);
        dprintf(atoi(getenv("fd_content")), "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", new_buffer_content, size, nmemb, filename_buf, old_return);
        // dprintf(121, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)ptr, size, nmemb, filename_buf, old_return);
        // printf("[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", (char *)ptr, size, nmemb, filename_buf, old_return);
    }

    return old_return;
}

int open(const char *pathname, int flags, ...)
{
    va_list args;
    mode_t mode = 0;

    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);

    int old_return;

    char realfilepath[1024] = "";
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_open = dlsym(handle, "open");
    }

    if (mode == 0)
        old_return = old_open(pathname, flags);
    else
        old_return = old_open(pathname, flags, mode);

    realpath(pathname, realfilepath);

    if (mode == 0)
    {
        dprintf(atoi(getenv("fd_content")), "[logger] open(\"%s\", %o) = %d\n", realfilepath, flags, old_return);
        // fprintf(stderr, "[logger] open(\"%s\", %o) = %d\n", realfilepath, flags, old_return);
        // dprintf(121, "[logger] open(\"%s\", %o) = %d\n", realfilepath, flags, old_return);
        // printf("[logger] open(\"%s\", %o) = %d\n", realfilepath, flags, old_return);
    }
    else
    {
        dprintf(atoi(getenv("fd_content")), "[logger] open(\"%s\", %o, %o) = %d\n", realfilepath, flags, mode, old_return);
        // fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", realfilepath, flags, mode, old_return);
        // dprintf(121, "[logger] open(\"%s\", %o, %o) = %d\n", realfilepath, flags, mode, old_return);
        // printf("[logger] open(\"%s\", %o, %o) = %d\n", realfilepath, flags, mode, old_return);
    }

    return old_return;
}

ssize_t read(int fd, void *buf, size_t count)
{
    int index;
    char filename[1024] = "";
    char filename_buf[1024] = "";
    struct stat fstat_buf;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_read = dlsym(handle, "read");
    }

    snprintf(filename, 1024, "/proc/%ld/fd/%d", (long)getpid(), fd);

    // if (readlink(filename, filename_buf, 1024) > 0)
    readlink(filename, filename_buf, 1024);

    ssize_t old_return = old_read(fd, buf, count);

    char *buffer_content = (char *)buf;

    int length;
    if (strlen(buffer_content) > 32)
        length = 32;
    else
        length = (int)strlen(buffer_content);

    char new_buffer_content[length + 1];
    // memset(new_buffer_content, '\0', length + 1);

    new_buffer_content[length] = '\0';

    for (index = 0; index < length; index++)
    {
        if (buffer_content[index] == '\0')
        {
            new_buffer_content[index] = '\0';
            break;
        }
        else if (isprint(buffer_content[index]) == 0)
            new_buffer_content[index] = (char)'.';
        else
            new_buffer_content[index] = (char)buffer_content[index];
    }

    dprintf(atoi(getenv("fd_content")), "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content, count, old_return);
    // fprintf(stderr, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content, count, old_return);
    // dprintf(121, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content, count, old_return);
    // printf("[logger] read(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content, count, old_return);

    // bzero(buffer_content, (int)old_return);
    bzero(new_buffer_content, length + 1);
    // bzero((char *)buf, (int)old_return);

    return old_return;
}

int remove(const char *pathname)
{
    char realfilepath[1024];
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_remove = dlsym(handle, "remove");
    }

    int old_return = old_remove(pathname);

    realpath(pathname, realfilepath);

    dprintf(atoi(getenv("fd_content")), "[logger] remove(\"%s\") = %d\n", realfilepath, old_return);
    // fprintf(stderr, "[logger] remove(\"%s\") = %d\n", realfilepath, old_return);
    // dprintf(121, "[logger] remove(\"%s\") = %d\n", realfilepath, old_return);
    // printf("[logger] remove(\"%s\") = %d\n", realfilepath, old_return);

    return old_return;
}

int rename(const char *oldpath, const char *newpath)
{
    char old_realfilepath[1024];
    char new_realfilepath[1024];
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_rename = dlsym(handle, "rename");
    }

    int old_return = old_rename(oldpath, newpath);

    realpath(oldpath, old_realfilepath);
    realpath(newpath, new_realfilepath);

    dprintf(atoi(getenv("fd_content")), "[logger] rename(\"%s\", \"%s\") = %d\n", old_realfilepath, new_realfilepath, old_return);
    // fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", old_realfilepath, new_realfilepath, old_return);
    // dprintf(121, "[logger] rename(\"%s\", \"%s\") = %d\n", old_realfilepath, new_realfilepath, old_return);
    // printf("[logger] rename(\"%s\", \"%s\") = %d\n", old_realfilepath, new_realfilepath, old_return);

    return old_return;
}

FILE *tmpfile(void)
{

    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_tmpfile = dlsym(handle, "tmpfile");
    }

    FILE *old_return = old_tmpfile();

    dprintf(atoi(getenv("fd_content")), "[logger] tmpfile() = %p\n", old_return);
    // fprintf(stderr, "[logger] tmpfile() = %p\n", old_return);
    // dprintf(121, "[logger] tmpfile() = %p\n", old_return);
    // printf("[logger] tmpfile() = %p\n", old_return);

    return old_return;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    int index;
    char filename[1024] = "";
    char filename_buf[1024] = "";
    void *handle = dlopen("libc.so.6", RTLD_LAZY);

    if (handle != NULL)
    {
        old_write = dlsym(handle, "write");
    }

    ssize_t old_return = old_write(fd, buf, count);

    snprintf(filename, 1024, "/proc/%ld/fd/%d", (long)getpid(), fd);

    char *buffer_content = (char *)buf;

    int length;
    if ((int)old_return > 32)
        length = 32;
    else
        length = (int)old_return;

    char new_buffer_content[length + 1];
    new_buffer_content[length] = '\0';
    // memset(new_buffer_content, '\0', length + 1);

    for (index = 0; index < length; index++)
    {
        if (isprint(buffer_content[index]) == 0)
            new_buffer_content[index] = '.';
        else
            new_buffer_content[index] = buffer_content[index];
    }

    if (readlink(filename, filename_buf, 1024) > 0)
    {
        dprintf(atoi(getenv("fd_content")), "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content, count, old_return);
        // fprintf(stderr, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content, count, old_return);
        // dprintf(121, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content_write, count, old_return);
        // printf("[logger] write(\"%s\", \"%s\", %ld) = %ld\n", filename_buf, new_buffer_content_write, count, old_return);
    }

    // bzero(buffer_content, (int)old_return);
    bzero(new_buffer_content, length + 1);
    // bzero((char *)buf, (int)old_return);

    return old_return;
}