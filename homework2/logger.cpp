#include <regex>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <filesystem>

using namespace std;

int main(int argc, char *argv[])
{

    setenv("fd_content", to_string(5).c_str(), 1);
    int exec_flag = 0, command_flag = 0, arg_end = 0;
    string exec_command = "", command = "";

    int opt;
    int o_flag = 0, p_flag = 0, double_dash_flag = 0;
    char *opt_string = ":p::o::";
    char option_o[100], option_p[100];
    char dircontent[256];
    getcwd(dircontent, 256);

    if (argc == 1)
    {
        printf("no command given.\n");
        exit(-1);
    }
    else if (argc > 1)
    {
        while ((opt = getopt(argc, argv, opt_string)) != -1)
        {
            switch (opt)
            {
            case 'o':
                if (strcmp(argv[optind], "--") != 0)
                {
                    sprintf(option_o, "%s", argv[optind]);
                    o_flag = 1;
                }
                break;
            case 'p':
                if (strcmp(argv[optind], "--") != 0)
                {
                    sprintf(option_p, "%s", argv[optind]);
                    p_flag = 1;
                }
                break;
            case '?':
                string filename(argv[0]);
                filename.erase(0, 1);
                cout << dircontent << filename << ": invalid option -- '" << (char)optopt << "'" << endl;
                cout << "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]" << endl;
                cout << "        -p: set the path to logger.so, default = ./logger.so" << endl;
                cout << "        -o: print output to file, print to \"stderr\" if no file specified" << endl;
                cout << "        --: separate the arguments for logger and for the command" << endl;
                exit(-1);
                break;
            }
        }

        for (int index = 1; index < argc; index++)
        {
            if (strcmp(argv[index], "--") == 0)
            {
                double_dash_flag = 1;
                for (int dash_index = index + 2; dash_index < argc; dash_index++)
                {
                    string tmp1;
                    exec_command += tmp1.assign(argv[dash_index]);
                    exec_command += " ";
                }
                break;
            }
        }

        if (double_dash_flag == 0)
        {
            exec_command = "";
            for (int index = 1; index < argc; index++)
            {
                string tmp1;
                exec_command += tmp1.assign(argv[index]);
                exec_command += " ";
            }
        }

        if (double_dash_flag == 1)
        {
            if (!o_flag && !p_flag)
            {
                exec_command = "";
                for (int index = 1; index < argc; index++)
                {
                    if (strcmp(argv[index], "--") != 0)
                    {
                        string tmp1;
                        exec_command += tmp1.assign(argv[index]);
                        exec_command += " ";
                    }
                }
            }
            if (o_flag || p_flag)
            {
                exec_command = "";
                for (int index = 1; index < argc; index++)
                {
                    if (strcmp(argv[index], "--") != 0 && strcmp(argv[index], "-p") != 0 && strcmp(argv[index], "-o") != 0 && strcmp(argv[index], option_p) != 0 && strcmp(argv[index], option_o) != 0)
                    {
                        string tmp1;
                        exec_command += tmp1.assign(argv[index]);
                        exec_command += " ";
                    }
                }
            }
        }
    }

    // cout << "exec_command: " << exec_command << endl;
    // cout << "option_p: " << option_p << endl;
    // cout << "option_o: " << option_o << endl;

    if (p_flag == 0)
        sprintf(option_p, "./logger.so");

    atoi(getenv("fd_content"));

    char total_exec[1024];
    if (o_flag)
        sprintf(total_exec, "LD_PRELOAD=%s %s %s>%s", option_p, exec_command.c_str(), getenv("fd_content"), option_o);
    else
        sprintf(total_exec, "LD_PRELOAD=%s %s %s>&2", option_p, exec_command.c_str(), getenv("fd_content"));
    system(total_exec);
    // cout << "total_exec: " << total_exec << endl;
    system("rm -rf 2");
    unsetenv("fd_content");
    return 0;
}