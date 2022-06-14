## Implement a 'lsof'-like program

In this homework, you have to implement the 'lsof' tool by yourself. 'lsof' is a tool to list open files. It can be used to list all the files opened by processes running in the system. The output of your homework is required to follow the spec strictly. The TAs will use the 'diff' tool to compare your output directly against our prepared sample test data.

### Program Arguments
Your program should work without any arguments. In the meantime, your program has to handle the following arguments properly:

- -c: a regular expression (REGEX) filter for filtering command line. For example -c sh would match bash, zsh, and share.  
- -t: a TYPE filter. Valid TYPE includes REG, CHR, DIR, FIFO, SOCK, and unknown. TYPEs other than the listed should be considered invalid. For invalid types, your program has to print out an error message Invalid TYPE option. in a single line and terminate your program.  
- -f: a regular expression (REGEX) filter for filtering filenames.  

A sample output from this homework is demonstrated as follows: 

```bash
$ ./hw1 | head -n 20
COMMAND         PID             USER            FD              TYPE            NODE            NAME
systemd         1               root            cwd             unknown                         /proc/1/cwd (Permission denied)
systemd         1               root            rtd             unknown                         /proc/1/root (Permission denied)
systemd         1               root            txt             unknown                         /proc/1/exe (Permission denied)
systemd         1               root            NOFD                                            /proc/1/fd (Permission denied)
kthreadd                2               root            cwd             unknown                         /proc/2/cwd (Permission denied)
kthreadd                2               root            rtd             unknown                         /proc/2/root (Permission denied)
kthreadd                2               root            txt             unknown                         /proc/2/exe (Permission denied)
kthreadd                2               root            NOFD                                            /proc/2/fd (Permission denied)
rcu_gp          3               root            cwd             unknown                         /proc/3/cwd (Permission denied)
rcu_gp          3               root            rtd             unknown                         /proc/3/root (Permission denied)
rcu_gp          3               root            txt             unknown                         /proc/3/exe (Permission denied)
rcu_gp          3               root            NOFD                                            /proc/3/fd (Permission denied)
rcu_par_gp              4               root            cwd             unknown                         /proc/4/cwd (Permission denied)
rcu_par_gp              4               root            rtd             unknown                         /proc/4/root (Permission denied)
rcu_par_gp              4               root            txt             unknown                         /proc/4/exe (Permission denied)
rcu_par_gp              4               root            NOFD                                            /proc/4/fd (Permission denied)
kworker/0:0H-events_highpri             6               root            cwd             unknown                         /proc/6/cwd (Permission denied)
kworker/0:0H-events_highpri             6               root            rtd             unknown                         /proc/6/root (Permission denied)
kworker/0:0H-events_highpri             6               root            txt             unknown                         /proc/6/exe (Permission denied)
...
```
