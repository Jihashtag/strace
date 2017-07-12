#include<stdio.h>
#include<stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "incl.h"
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/reg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/user.h>
#include <string.h>

int	epur_str(char *s)
{
	int	i = 0;
	int	j = 32;
	int	k = 0;
	char	s2[33];

	while (i < j && s[i])
	{
		if ((isspace(s[i]) && s[i] != ' ') || s[i] == '\\')
		{
			s2[i + k] = '\\';
			k++;
			switch (s[i])
			{
				case '\n':
				s2[i + k] = 'n';
				break ;
				case '\t':
				s2[i + k] = 't';
				break ;
				case '\r':
				s2[i + k] ='r';
				break ;
				case '\\':
				s2[i + k] = '\\';
				break ;
				case '\f':
				s2[i + k] = 'f';
				break ;
				case '\v':
				s2[i + k] = 'v';
				break ;
			}
			j--;
		}
		else
			s2[i + k] = s[i];
		i++;
	}
	if (i > j && i + k >= 32)
		s2[32] = '\0';
	else
		s2[i + k] = '\0';
	i = 0;
	while (s2[i])
	{
		s[i] = s2[i];
		i++;
	}
	s[i] = 0;
	return (i);
}
void	print_args(long *args, int size, pid_t pid, call_ent sys)
{
	int		i = 0;
	char		str[33];

	while (i < size)
	{
		if (sys.t[i] == STR || sys.t[i] == STRSTOP)
			putstr(sys.t[i], args[i]);
		else if (sys.t[i] == PTR)
			if (!(void *)args[i])
				printf("NULL");
			else
				printf("%p", (void *)args[i]);
		else
			putint(sys.t[i], args[i]);
		i++;
		if (i < size)
			printf(", ");
	}
}

void	aff_arg(int sysnum, pid_t pid)
{
	long	args[7] = {0, 0, 0, 0, 0, 0, 0};
	int	argnum = sys_list[sysnum].num;
	int	i;

	i = 0;
	while (i < argnum)
	{
		errno = 0;
		switch (i)
		{
			case 0:
			args[i] = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EBX);
			break ;
			case 1:
			args[i] = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ECX);
			break ;
			case 2:
			args[i] = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EDX);
			break ;
			case 3:
			args[i] = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ESI);
			break ;
			case 4:
			args[i] = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EDI);
			break ;
			case 5:
			args[i] = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EBP);
			break ;
		}
		if (errno)
			args[i] = '?';
		i++;
	}
	print_args(args, argnum, pid,	sys_list[sysnum]);
}

sigset_t	*blocked(int i)
{
	static sigset_t	block;

	if (i == 1)
		return (&block);
	sigaddset(&block, SIGHUP);
	sigaddset(&block, SIGINT);
	sigaddset(&block, SIGPIPE);
	sigaddset(&block, SIGQUIT);
	sigaddset(&block, SIGTERM);
	return (&block);
}

void	ft_strace(pid_t pid, siginfo_t sig)
{
	int	status;
	long int	syscallval;

	waitpid(pid, &status, 0);
	if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
	{
		syscallval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*ORIG_EAX);
		printf("%s(", sys_list[syscallval].fct_name);
		aff_arg(syscallval, pid);
		errno = 0;
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		if (errno)
			perror("./ft_strace");
		waitpid(pid, &status, 0);
		printf(") = ");
		errno = 0;
		syscallval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*EAX);
		if (errno)
			printf("?\n");
		else
			printf("%ld\n", syscallval);
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
	}
	else if (WIFEXITED(status))
	{
		printf("+++ exited with %d +++\n", WEXITSTATUS(status));
		_exit(0);
	}
	else if (WIFSTOPPED(status))
	{
		ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig);
		printf("--- %s {si_signo=%s, si_code=%d} ---\n", \
		sigl[sig.si_signo].s, sigl[sig.si_signo].s, sig.si_code);
		ptrace(PTRACE_SYSCALL, pid, NULL, sig.si_signo);
	}
	else
	{
		printf("Process %d detached\n", pid);
		_exit(status);
	}
}

void	parsep(char *s)
{
	while (*s)
	{
		if (*s == ':')
			*s = '\0';
		s++;
	}
}

int	findfile(char **av)
{
	static	char	s[1025];
	char		*path = getenv("PATH");
	char		*end = path + strlen(path);
	int		f = 1;

	parsep(path);
	while (path <= end)
	{
		if (f)
		{
			strcpy(s, path);
			strcat(s, "/");
			strcat(s, av[1]);
			if (access(s, X_OK) == 0)
			{
				av[1] = s;
				f = 0;
			}
		}
		path += strlen(path) + 1;
		if (path <= end)
			path[-1] = ':';
	}
	return (f);
}

int	main(int ac, char **av, char **env)
{
	pid_t	pid;

	if (ac < 2)
	{
		fprintf(stderr, "Usage: ft_strace PROG [ARGS]\n");
		_exit(1);
	}
	if (access(av[1], X_OK) && findfile(av))
	{
		fprintf(stderr, "%s: %s: file not found\n", av[0], av[1]);
		_exit(1);
	}
	pid = fork();
	if (pid == 0)
	{
		kill(getpid(), SIGSTOP);
		av++;
		execve(av[0], av, env);
		fprintf(stderr, "Error Executing cmd\n");
		_exit (1);
	}
	sigset_t	empty;
	sigemptyset(&empty);
	sigprocmask(SIG_SETMASK, &empty, NULL);
	waitpid(pid, 0, WUNTRACED);
	sigprocmask(SIG_BLOCK, blocked(0), NULL);
	errno = 0;
	siginfo_t sig;
	if (errno)
		perror("./ft_strace");
	errno = 0;
	ptrace(PTRACE_SEIZE, pid, 0, 0);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
	if (errno)
		perror("./ft_strace");
	ptrace(PTRACE_SYSCALL, pid, 0, 0);
	while (1)
		ft_strace(pid, sig);
	return (0);
}
