#ifndef INC_H
#define INC_H
#include <sys/syscall.h>

typedef enum {
	CHAR = 1,
	SHORT = 2,
	INT = 3,
	SIZE_T = 4,
	LONG = 5,
	LONGLONG = 6,
	PTR = 7,
	STR = 8,
	STRSTOP = 9,
	INTTAB = 10,
	UINT = 11,
	ULONG = 12,
	INT2 = 13,
	UINTTAB = 14,
	STRTAB = 15,
	ULONGTAB = 16
} TYPES;

typedef struct	sys_call_entry{
	int	num;
	char	*fct_name;
	TYPES	t[6];
}	call_ent;

typedef struct	sig_list{
	char	*s;
	int	i;
}	t_sig_lst;

t_sig_lst	sigl[32] = {
	{"Unknown", 0},
	{"SIGHUP", 1},
	{"SIGINT", 2},
	{"SIGQUIT", 3},
	{"SIGILL", 4},
	{"SIGTRAP", 5},
	{"SIGABRT", 6},
	{"SIGBUS", 7},
	{"SIGFPE", 8},
	{"SIGKILL", 9},
	{"SIGUSR1", 10},
	{"SIGSEGV", 11},
	{"SIGUSR2", 12},
	{"SIGPIPE", 13},
	{"SIGALRM", 14},
	{"SIGTERM", 15},
	{"SIGSTKFLT", 16},
	{"SIGCHLD", 17},
	{"SIGCONT", 18},
	{"SIGSTOP", 19},
	{"SIGTSTP", 20},
	{"SIGTTIN", 21},
	{"SIGTTOU", 22},
	{"SIGURG", 23},
	{"SIGXCPU", 24},
	{"SIGXFSZ", 25},
	{"SIGVTALRM", 26},
	{"SIGPROF", 27},
	{"SIGWINCH", 28},
	{"SIGPOLL", 29},
	{"SIGPWR", 30},
	{"SIGSYS", 31}
};

call_ent sys_list[] = {
	{ 0,	"restart_syscall" ,{}}, /* 0 */
	{ 1,	"_exit"		,	{INT}}, /* 1 */
	{ 0,	"fork"		,{}}, /* 2 */
	{ 3,	"read"		,	{UINT,		PTR,		SIZE_T}}, /* 3 */
	{ 3,	"write"		,	{UINT,		STRSTOP,	SIZE_T}}, /* 4 */
	{ 3,	"open"		,	{STR,		INT,		INT}}, /* 5 */
	{ 1,	"close"		,	{UINT}}, /* 6 */
	{ 3,	"waitpid"	,	{INT,		UINTTAB,	INT}}, /* 7 */
	{ 2,	"creat"		,	{STR,		INT}}, /* 8 */
	{ 2,	"link"		,	{STR,		STR}}, /* 9 */
	{ 1,	"unlink"	,	{STR}}, /* 10 */
	{ 3,	"execve"	,	{STR,		STRTAB,		STRTAB}}, /* 11 */
	{ 1,	"chdir"		,	{STR}}, /* 12 */
	{ 1,	"time"		,	{PTR/*_TIME_T*/}}, /* 13 */
	{ 3,	"mknod"		,	{STR,		PTR/*_MODE_T*/,	PTR/*_DEV_T*/}}, /* 14 */
	{ 2,	"chmod"		,	{STR,		PTR/*MODE_T*/}}, /* 15 */
	{ 3,	"lchown"	,	{STR,		INT/*UID_T*/,	INT/*GUID_T*/}}, /* 16 */
	{ 0,	"break"		,{}}, /* 17 */
	{ 2,	"oldstat"	/*LATER*/ ,{}}, /* 18 */
	{ 3,	"lseek"		,	{INT,		UINT/*OFF_T*/,	INT}}, /* 19 */
	{ 0,	"getpid"	,{}}, /* 20 */
	{ 5,	"mount"		,	{STR,		STR,		STR,	PTR,	PTR}}, /* 21 */
	{ 1,	"oldumount"	,	{STR}}, /* 22 */
	{ 1,	"setuid"	,	{INT/*UID_T*/}}, /* 23 */
	{ 0,	"getuid"	,{}}, /* 24 */
	{ 1,	"stime"		,	{PTR/*TIME_T*/}}, /* 25 */
	{ 4,	"ptrace"	,	{LONG,		INT,		LONG,	LONG}}, /* 26 */
	{ 1,	"alarm"		,	{UINT}}, /* 27 */
	{ 2,	"oldfstat"	/*LATER*/,{}}, /* 28 */
	{ 0,	"pause"		,{}}, /* 29 */
	{ 2,	"utime"		,	{STR,		PTR/*STRUCT_UTIMBUF*/}}, /* 30 */
	{ 2,	"stty"		/*LATER*/,{}}, /* 31 */
	{ 2,	"gtty"		/*LATER*/,{}}, /* 32 */
	{ 2,	"access"	,	{STR,		INT}}, /* 33 */
	{ 1,	"nice"		,	{INT}}, /* 34 */
	{ 0,	"ftime"		,{}}, /* 35 */
	{ 0,	"sync"		,{}}, /* 36 */
	{ 2,	"kill"		,	{INT}}, /* 37 */
	{ 2,	"rename"	,	{STR,		STR}}, /* 38 */
	{ 2,	"mkdir"		,	{STR,		PTR/*MODE_T*/}}, /* 39 */
	{ 1,	"rmdir"		,	{STR}}, /* 40 */
	{ 1,	"dup"		,	{INT}}, /* 41 */
	{ 1,	"pipe"		,	{INT2}}, /* 42 */
	{ 1,	"times"		,	{PTR/*S_TMS*/}}, /* 43 */
	{ 0,	"prof"		,{}}, /* 44 */
	{ 1,	"brk"		,	{PTR}}, /* 45 */
	{ 1,	"setgid"	,	{PTR/*GID_t*/}}, /* 46 */
	{ 0,	"getgid"	,{}}, /* 47 */
	{ 2,	"signal"	,	{INT,	PTR/*SIGH*/}}, /* 48 */
	{ 0,	"geteuid"	,{}}, /* 49 */
	{ 0,	"getegid"	,{}}, /* 50 */
	{ 1,	"acct"		,	{STR}}, /* 51 */
	{ 2,	"umount"	,	{STR,	INT}}, /* 52 */
	{ 0,	"lock"		,{}}, /* 53 */
	{ 3,	"ioctl"		,	{UINT,	UINT,	ULONG}}, /* 54 */
	{ 3,	"fcntl"		,	{UINT,	UINT,	ULONG}}, /* 55 */
	{ 0,	"mpx"		,{}}, /* 56 */
	{ 2,	"setpgid"	,	{INT/*PID_T*/,	INT/*PID_T*/}}, /* 57 */
	{ 2,	"ulimit"	,	{INT,	LONG}}, /* 58 */
	{ 1,	"oldolduname"	,	{PTR/*S_UTSNAME*/}}, /* 59 */
	{ 1,	"umask"		,	{INT}}, /* 60 */
	{ 1,	"chroot"	,	{STR}}, /* 61 */
	{ 2,	"ustat"		,	{PTR,PTR/*SEE MAN*/}}, /* 62 */
	{ 2,	"dup2"		,	{UINT,	UINT}}, /* 63 */
	{ 0,	"getppid"	,{}}, /* 64 */
	{ 0,	"getpgrp"	,{}}, /* 65 */
	{ 0,	"setsid"	,{}}, /* 66 */
	{ 3,	"sigaction"	,	{INT,	PTR,	PTR/*MAN*/}}, /* 67 */
	{ 0,	"sgetmask"	,{}}, /* 68 */
	{ 1,	"ssetmask"	,	{INT}}, /* 69 */
	{ 2,	"setreuid"	,	{PTR,	PTR /*MAN*/}}, /* 70 */
	{ 2,	"setregid"	,	{PTR,	PTR /*MAN*/}}, /* 71 */
	{ 3,	"sigsuspend"	,	{INT,	INT,	PTR/*MAN*/}}, /* 72 */
	{ 1,	"sigpending"	,	{PTR}/*MAN*/}, /* 73 */
	{ 2,	"sethostname"	,	{STRSTOP,	INT}}, /* 74 */
	{ 2,	"setrlimit"	,	{UINT,	PTR/*MAN*/}}, /* 75 */
	{ 2,	"old_getrlimit"	,	{UINT,	PTR/*MAN*/}}, /* 76 */
	{ 2,	"getrusage"	,	{INT,	PTR/*MAN*/}}, /* 77 */
	{ 2,	"gettimeofday"	,	{PTR,	PTR/*MAN*/}}, /* 78 */
	{ 2,	"settimeofday"	,	{PTR,	PTR/*MAN*/}}, /* 79 */
	{ 2,	"getgroups"	,	{INT,	PTR/*MAN*/}}, /* 80 */
	{ 2,	"setgroups"	,	{INT,	PTR/*MAN*/}}, /* 81 */
	{ 1,	"oldselect"	,	{PTR}}, /* 82 */
	{ 2,	"symlink"	,	{STR,	STR}}, /* 83 */
	{ 2,	"oldlstat"	,	{STR,	PTR/*MAN*/}}, /* 84 */
	{ 3,	"readlink"	,	{STR,	STR,	INT}}, /* 85 */
	{ 1,	"uselib"	,	{STR}}, /* 86 */
	{ 2,	"swapon"	,	{STR,	INT}}, /* 87 */
	{ 4,	"reboot"	,	{INT,	INT,	UINT,	PTR}}, /* 88 */
	{ 3,	"readdir"	,	{INT,	PTR/*MAN*/,	UINT}}, /* 89 */
	{ 6,	"old_mmap"	,{}}, /* 90 */
	{ 2,	"munmap"	,	{ULONG,	SIZE_T}}, /* 91 */
	{ 2,	"truncate"	,	{STR,	LONG}}, /* 92 */
	{ 2,	"ftruncate"	,	{UINT,	ULONG}}, /* 93 */
	{ 2,	"fchmod"	,	{UINT,	PTR/*MODE_T*/}}, /* 94 */
	{ 3,	"fchown"	,	{UINT,	PTR,	PTR}/*MAN*/}, /* 95 */
	{ 2,	"getpriority"	,	{INT,	INT}}, /* 96 */
	{ 3,	"setpriority"	,	{INT,	INT,	INT}}, /* 97 */
	{ 4,	"profil"	,{}}, /* 98 */
	{ 2,	"statfs"	,	{STR,	PTR}}, /* 99 */
	{ 2,	"fstatfs"	,	{UINT,	PTR}}, /* 100 */
	{ 3,	"ioperm"	,	{ULONG,	ULONG,	INT}}, /* 101 */
	{ 2,	"socketcall"	,	{INT,	PTR}}, /* 102 */
	{ 3,	"syslog"	,	{INT,	STR,	INT}}, /* 103 */
	{ 3,	"setitimer"	,	{INT,	PTR,	INT}}, /* 104 */
	{ 2,	"getitimer"	,	{INT,	PTR}}, /* 105 */
	{ 2,	"stat"		,	{STR,	PTR}}, /* 106 */
	{ 2,	"lstat"		,	{STR,	PTR}}, /* 107 */
	{ 2,	"fstat"		,	{INT,	PTR}}, /* 108 */
	{ 1,	"olduname"	,	{PTR}}, /* 109 */
	{ 1,	"iopl"		,	{UINT}}, /* 110 */
	{ 0,	"vhangup"	,{}}, /* 111 */
	{ 0,	"idle"		,{}}, /* 112 */
	{ 1,	"vm86old"	,	{PTR}}, /* 113 */
	{ 4,	"wait4"		,	{INT,	INTTAB,	INT,	PTR}}, /* 114 */
	{ 1,	"swapoff"	,	{STR}}, /* 115 */
	{ 1,	"sysinfo"	,	{PTR}}, /* 116 */
	{ 6,	"ipc"		,{}}, /* 117 */
	{ 1,	"fsync"		,	{UINT}}, /* 118 */
	{ 0,	"sigreturn"	,{}}, /* 119 */
	{ 5,	"clone"		,	{ULONG,	ULONG,	ULONG,	ULONG,	PTR}}, /* 120 */
	{ 2,	"setdomainname"	,	{STR,	INT}}, /* 121 */
	{ 1,	"uname"		,	{PTR}}, /* 122 */
	{ 3,	"modify_ldt"	,	{INT,	PTR,	ULONG}}, /* 123 */
	{ 1,	"adjtimex"	,	{PTR}}, /* 124 */
	{ 3,	"mprotect"	,	{ULONG,	SIZE_T,	ULONG}}, /* 125 */
	{ 3,	"sigprocmask"	,	{INT,	PTR,	PTR}}, /* 126 */
	{ 2,	"create_module"	,{}}, /* 127 */
	{ 3,	"init_module"	,	{PTR,	ULONG,	STR}}, /* 128 */
	{ 2,	"delete_module"	,	{STR,	UINT}}, /* 129 */
	{ 1,	"get_kernel_syms",{}}, /* 130 */
	{ 4,	"quotactl"	,	{UINT,	STR,	PTR}}, /* 131 */
	{ 1,	"getpgid"	,	{INT/*PID_T*/}}, /* 132 */
	{ 1,	"fchdir"	,	{UINT}}, /* 133 */
	{ 0,	"bdflush"	,{}}, /* 134 */
	{ 3,	"sysfs"		,	{INT,	ULONG,	ULONG}}, /* 135 */
	{ 1,	"personality"	,	{UINT}}, /* 136 */
	{ 5,	"afs_syscall"	,{}}, /* 137 */
	{ 1,	"setfsuid"	,	{INT}}, /* 138 */
	{ 1,	"setfsgid"	,	{INT}}, /* 139 */
	{ 5,	"_llseek"	,	{UINT,	ULONG,	ULONG,	PTR,	UINT}}, /* 140 */
	{ 3,	"getdents"	,	{UINT,	PTR,	UINT}}, /* 141 */
	{ 5,	"select"	,	{INT,	PTR,	PTR,	PTR,	PTR}}, /* 142 */
	{ 2,	"flock"		,	{UINT,	UINT}}, /* 143 */
	{ 3,	"msync"		,	{ULONG,	SIZE_T,	INT}}, /* 144 */
	{ 3,	"readv"		,	{ULONG,	PTR,	ULONG}}, /* 145 */
	{ 3,	"writev"	,	{ULONG,	PTR,	ULONG}}, /* 146 */
	{ 1,	"getsid"	,	{INT}}, /* 147 */
	{ 1,	"fdatasync"	,	{UINT}}, /* 148 */
	{ 1,	"sysctl"	,	{PTR}}, /* 149 */
	{ 2,	"mlock"		,	{ULONG,	SIZE_T}}, /* 150 */
	{ 2,	"munlock"	,	{ULONG,	SIZE_T}}, /* 151 */
	{ 1,	"mlockall"	,	{INT}}, /* 152 */
	{ 0,	"munlockall"	,{}}, /* 153 */
	{ 0,	"sched_setparam",{}}, /* 154 */
	{ 2,	"sched_getparam",	{INT,	PTR}}, /* 155 */
	{ 3,	"sched_setscheduler",	{INT,	INT,	PTR}}, /* 156 */
	{ 1,	"sched_getscheduler",	{INT}}, /* 157 */
	{ 0,	"sched_yield"	,{}}, /* 158 */
	{ 1,	"sched_get_priority_max",	{INT}}, /* 159 */
	{ 1,	"sched_get_priority_min",	{INT}}, /* 160 */
	{ 2,	"sched_rr_get_interval",	{INT,	PTR}}, /* 161 */
	{ 2,	"nanosleep"	,	{PTR,	PTR}}, /* 162 */
	{ 5,	"mremap"	,	{ULONG,	ULONG,	ULONG,	ULONG,	ULONG}}, /* 163 */
	{ 3,	"setresuid"	,	{PTR,	PTR,	PTR}}, /* 164 */
	{ 3,	"getresuid"	,	{PTR,	PTR,	PTR}}, /* 165 */
	{ 5,	"vm86"		,	{/*man*/}}, /* 166 */
	{ 5,	"query_module"	,{}}, /* 167 */
	{ 3,	"poll"		,	{PTR,	UINT,	LONG}}, /* 168 */
	{ 3,	"nfsservctl"	,	{INT,	PTR,	PTR}}, /* 169 */
	{ 3,	"setresgid"	,	{PTR,	PTR,	PTR}}, /* 170 */
	{ 3,	"getresgid"	,	{PTR,	PTR,	PTR}}, /* 171 */
	{ 5,	"prctl"		,	{INT,	ULONG,	ULONG,	ULONG,	ULONG}}, /* 172 */
	{ 0,	"rt_sigreturn"	,{}}, /* 173 */
	{ 4,	"rt_sigaction"	,	{INT,	PTR,	PTR,	SIZE_T}}, /* 174 */
	{ 4,	"rt_sigprocmask",	{INT,	PTR,	PTR,	SIZE_T}}, /* 175 */
	{ 2,	"rt_sigpending"	,	{PTR,	SIZE_T}}, /* 176 */
	{ 4,	"rt_sigtimedwait",	{PTR,	PTR,	PTR,	SIZE_T}}, /* 177 */
	{ 3,	"rt_sigqueueinfo",	{INT,	INT,	PTR}}, /* 178 */
	{ 2,	"rt_sigsuspend"	,	{PTR,	SIZE_T}}, /* 179 */
	{ 5,	"pread64"	,	{STR,	SIZE_T,	ULONG}}, /* 180 */
	{ 5,	"pwrite64"	,	{STR,	SIZE_T,	ULONG}}, /* 181 */
	{ 3,	"chown"		,	{STR,	PTR,	PTR}}, /* 182 */
	{ 2,	"getcwd"	,	{STR,	ULONG}}, /* 183 */
	{ 2,	"capget"	,	{PTR,	PTR}}, /* 184 */
	{ 2,	"capset"	,	{PTR,	PTR}}, /* 185 */
	{ 2,	"sigaltstack"	,	{PTR,	PTR}}, /* 186 */
	{ 4,	"sendfile"	,	{INT,	INT,	PTR,	SIZE_T}}, /* 187 */
	{ 5,	"getpmsg"	,{}}, /* 188 */
	{ 5,	"putpmsg"	,{}}, /* 189 */
	{ 0,	"vfork"		,{}}, /* 190 */
	{ 2,	"getrlimit"	,	{UINT,	PTR}}, /* 191 */
	{ 6,	"mmap2"		,{}}, /* 192 */
	{ 3,	"truncate64"	,	{STR,	PTR}}, /* 193 */
	{ 3,	"ftruncate64"	,	{UINT,	PTR}}, /* 194 */
	{ 2,	"stat64"	,	{STR,	PTR}}, /* 195 */
	{ 2,	"lstat64"	,	{STR,	PTR}}, /* 196 */
	{ 2,	"fstat64"	,	{INT,	PTR}}, /* 197 */
	{ 3,	"lchown32"	,	{STR,	INT,	INT}}, /* 198 */
	{ 0,	"getuid32"	,{}}, /* 199 */

	{ 0,	"getgid32"	,{}}, /* 200 */
	{ 0,	"geteuid32"	,{}}, /* 201 */
	{ 0,	"getegid32"	,{}}, /* 202 */
	{ 2,	"setreuid32"	,	{INT,	INT}}, /* 203 */
	{ 2,	"setregid32"	,	{INT,	INT}}, /* 204 */
	{ 2,	"getgroups32"	,	{INT,	PTR}}, /* 205 */
	{ 2,	"setgroups32"	,	{INT,	PTR}}, /* 206 */
	{ 3,	"fchown32"	,	{UINT,	INT,	INT}}, /* 207 */
	{ 3,	"setresuid32"	,	{INT,	INT,	INT}}, /* 208 */
	{ 3,	"getresuid32"	,	{PTR,	PTR,	PTR}}, /* 209 */
	{ 3,	"setresgid32"	,	{INT,	INT	,INT}}, /* 210 */
	{ 3,	"getresgid32"	,	{PTR,	PTR,	PTR}}, /* 211 */
	{ 3,	"chown32"	,	{STR,	INT,	INT}}, /* 212 */
	{ 1,	"setuid32"	,	{INT}}, /* 213 */
	{ 1,	"setgid32"	,	{INT}}, /* 214 */
	{ 1,	"setfsuid32"	,	{INT}}, /* 215 */
	{ 1,	"setfsgid32"	,	{INT}}, /* 216 */
	{ 2,	"pivot_root"	,	{STR,	STR}}, /* 217 */
	{ 3,	"mincore"	,	{ULONG,	SIZE_T,	STR}}, /* 218 */
	{ 3,	"madvise"	,	{ULONG,	SIZE_T,	INT}}, /* 219 */
	{ 3,	"getdents64"	,	{UINT,	PTR,	UINT}}, /* 220 */
	{ 3,	"fcntl64"	,	{UINT,	UINT,	ULONG}}, /* 221 */
	{ 6,	NULL		,{}}, /* 222 */
	{ 5,	"security"	,{}}, /* 223 */
	{ 0,	"gettid"	,{}}, /* 224 */
	{ 4,	"readahead"	,	{INT,	PTR,	SIZE_T}}, /* 225 */
	{ 5,	"setxattr"	,	{STR,	STR,	PTR,	SIZE_T,	INT}}, /* 226 */
	{ 5,	"lsetxattr"	,	{STR,	STR,	PTR,SIZE_T,	INT}}, /* 227 */
	{ 5,	"fsetxattr"	,	{INT,	STR,	PTR,	SIZE_T,	INT}}, /* 228 */
	{ 4,	"getxattr"	,	{STR,	STR,	PTR,	SIZE_T}}, /* 229 */
	{ 4,	"lgetxattr"	,	{STR,	STR,	PTR,	SIZE_T}}, /* 230 */
	{ 4,	"fgetxattr"	,	{INT,	STR,	PTR,	SIZE_T}}, /* 231 */
	{ 3,	"listxattr"	,	{STR,	STR,	SIZE_T}}, /* 232 */
	{ 3,	"llistxattr"	,	{STR,	STR,	SIZE_T}}, /* 233 */
	{ 3,	"flistxattr"	,	{INT,	STR,	SIZE_T}}, /* 234 */
	{ 2,	"removexattr"	,	{STR,	STR}}, /* 235 */
	{ 2,	"lremovexattr"	,	{STR,	STR}}, /* 236 */
	{ 2,	"fremovexattr"	,	{INT,	STR}}, /* 237 */
	{ 2,	"tkill"		,	{INT,	INT}}, /* 238 */
	{ 4,	"sendfile64"	,	{INT,	INT,	PTR,	SIZE_T}}, /* 239 */
	{ 6,	"futex"		,{}}, /* 240 */
	{ 3,	"sched_setaffinity",	{INT,	UINT,	ULONGTAB}},/* 241 */
	{ 3,	"sched_getaffinity",	{INT,	UINT,	ULONGTAB}},/* 242 */
	{ 1,	"set_thread_area",	{PTR}}, /* 243 */
	{ 1,	"get_thread_area",	{PTR}}, /* 244 */
	{ 2,	"io_setup"	,	{PTR,	PTR}}, /* 245 */
	{ 1,	"io_destroy"	,	{PTR}}, /* 246 */
	{ 5,	"io_getevents"	,	{PTR,	LONG,	LONG,	PTR,	PTR}}, /* 247 */
	{ 3,	"io_submit"	,	{PTR,	LONG,	PTR}}, /* 248 */
	{ 3,	"io_cancel"	,	{PTR,	PTR,	PTR}}, /* 249 */
	{ 5,	"fadvise64"	,	{INT,	PTR,	SIZE_T,	INT,	PTR}}, /* 250 */
	{ 6,	NULL		,{}}, /* 251 */
	{ 1,	"exit_group"	,	{INT}}, /* 252 */
	{ 4,	"lookup_dcookie",	{PTR,	STR,	SIZE_T,	INT}}, /* 253 */
	{ 1,	"epoll_create"	,	{INT}}, /* 254 */
	{ 4,	"epoll_ctl"	,	{INT,	INT,	INT,	PTR}}, /* 255 */
	{ 4,	"epoll_wait"	,	{INT,	PTR,	INT,	INT}}, /* 256 */
	{ 5,	"remap_file_pages",	{ULONG,	ULONG,	ULONG,	ULONG}}, /* 257 */
	{ 1,	"set_tid_address",	{INTTAB}}, /* 258 */
	{ 3,	"timer_create"	,	{PTR,	PTR,	PTR}}, /* 259 */
	{ 4,	"timer_settime"	,	{PTR,	INT,	PTR,	PTR,	PTR}}, /* 260 */
	{ 2,	"timer_gettime"	,	{PTR,	PTR}}, /* 261 */
	{ 1,	"timer_getoverrun",	{PTR}}, /* 262 */
	{ 1,	"timer_delete"	,	{PTR}}, /* 263 */
	{ 2,	"clock_settime"	,	{PTR,	PTR}}, /* 264 */
	{ 2,	"clock_gettime"	,	{PTR,	PTR}}, /* 265 */
	{ 2,	"clock_getres"	,	{PTR,	PTR}}, /* 266 */
	{ 4,	"clock_nanosleep",	{PTR,	INT,	PTR,	PTR}}, /* 267 */
	{ 3,	"statfs64"	,	{STR,	SIZE_T,	PTR}}, /* 268 */
	{ 3,	"fstatfs64"	,	{UINT,	SIZE_T,	PTR}}, /* 269 */
	{ 3,	"tgkill"	,	{INT,	INT,	INT}}, /* 270 */
	{ 2,	"utimes"	,	{STR,	PTR}}, /* 271 */
	{ 6,	"fadvise64_64"	,	{INT,	PTR,	PTR,	INT}}, /* 272 */
	{ 5,	"vserver"	,{}}, /* 273 */
	{ 6,	"mbind"		,{}}, /* 274 */
	{ 5,	"get_mempolicy"	,	{INTTAB,	ULONGTAB,	ULONG,	ULONG,	ULONG}}, /* 275 */
	{ 3,	"set_mempolicy"	,	{INT,	ULONGTAB,	ULONG}}, /* 276 */
	{ 4,	"mq_open"	,	{STR,	INT,	PTR,	PTR}}, /* 277 */
	{ 1,	"mq_unlink"	,	{STR}}, /* 278 */
	{ 5,	"mq_timedsend"	,	{PTR,	STR,	SIZE_T,	UINTTAB,	PTR}}, /* 279 */
	{ 5,	"mq_timedreceive",	{PTR,	STR,	SIZE_T,	UINTTAB,	PTR}}, /* 280 */
	{ 2,	"mq_notify"	,	{PTR,	PTR}}, /* 281 */
	{ 3,	"mq_getsetattr"	,	{PTR,	PTR,	PTR}}, /* 282 */
	{ 4,	"kexec_load"	,	{ULONG,	ULONG,	PTR,	ULONG}}, /* 283 */
	{ 5,	"waitid"	,	{INT,	INT,	PTR,	INT,	PTR}}, /* 284 */
	{ 6,	NULL		,{}}, /* 285 */
	{ 5,	"add_key"	,	{STR,	STR,	PTR,	SIZE_T,	PTR}}, /* 286 */
	{ 4,	"request_key"	,	{STR,	STR,	STR,	PTR}}, /* 287 */
	{ 5,	"keyctl"	,	{INT,	ULONG,	ULONG,	ULONG,	ULONG}}, /* 288 */
	{ 3,	"ioprio_set"	,	{INT,	INT,	INT}}, /* 289 */
	{ 2,	"ioprio_get"	,	{INT,	INT}}, /* 290 */
	{ 0,	"inotify_init"	,{}}, /* 291 */
	{ 3,	"inotify_add_watch",	{INT,	STR,	PTR}}, /* 292 */
	{ 2,	"inotify_rm_watch",	{INT,	PTR}}, /* 293 */
	{ 4,	"migrate_pages"	,	{INT,	ULONG,	ULONGTAB,	ULONG}}, /* 294 */
	{ 4,	"openat"	,	{INT,	STR,	INT,	INT}}, /* 295 */
	{ 3,	"mkdirat"	,	{INT,	STR,	INT}}, /* 296 */
	{ 4,	"mknodat"	,	{INT,	STR,	INT,	PTR}}, /* 297 */
	{ 5,	"fchownat"	,	{INT,	STR,	PTR,	PTR,	INT}}, /* 298 */
	{ 3,	"futimesat"	,	{INT,	STR,	PTR}}, /* 299 */
	{ 4,	"fstatat64"	,	{INT,	STR,	PTR,	INT}}, /* 300 */
	{ 3,	"unlinkat"	,	{INT,	STR,	INT}}, /* 301 */
	{ 4,	"renameat"	,	{INT,	STR,	INT,	STR}}, /* 302 */
	{ 5,	"linkat"	,	{INT,	STR,	INT,	STR,	INT}}, /* 303 */
	{ 3,	"symlinkat"	,	{STR,	INT,	STR}}, /* 304 */
	{ 4,	"readlinkat"	,	{INT,	STR,	STR,	INT}}, /* 305 */
	{ 3,	"fchmodat"	,	{INT,	STR,	PTR}}, /* 306 */
	{ 3,	"faccessat"	,	{INT,	STR,	INT}}, /* 307 */
	{ 6,	"pselect6"	,{}}, /* 308 */
	{ 5,	"ppoll"		,	{PTR,	UINT,	PTR,	PTR,	SIZE_T}}, /* 309 */
	{ 1,	"unshare"	,	{ULONG}}, /* 310 */
	{ 2,	"set_robust_list",	{PTR,	SIZE_T}}, /* 311 */
	{ 3,	"get_robust_list",	{INT,	PTR,	SIZE_T}}, /* 312 */
	{ 6,	"splice"	,{}}, /* 313 */
	{ 6,	"sync_file_range",	{INT,	PTR,	PTR,	UINT}}, /* 314 */
	{ 4,	"tee"		,	{INT,	INT,	SIZE_T,	INT}}, /* 315 */
	{ 4,	"vmsplice"	,	{INT,	PTR,	ULONG,	UINT}}, /* 316 */
	{ 6,	"move_pages"	,{}}, /* 317 */
	{ 3,	"getcpu"	,	{PTR,	PTR,	PTR}}, /* 318 */
	{ 6,	"epoll_pwait"	,{}}, /* 319 */
	{ 4,	"utimensat"	,	{INT,	STR,	PTR,	INT}}, /* 320 */
	{ 3,	"signalfd"	,	{INT,	PTR,	SIZE_T}}, /* 321 */
	{ 2,	"timerfd_create",	{INT,	INT}}, /* 322 */
	{ 1,	"eventfd"	,	{UINT}}, /* 323 */
	{ 6,	"fallocate"	,	{INT,	INT,	PTR,	PTR}}, /* 324 */
	{ 4,	"timerfd_settime",	{INT,	INT,	PTR,	PTR}}, /* 325 */
	{ 2,	"timerfd_gettime",	{INT,	PTR}}, /* 326 */
	{ 4,	"signalfd4"	,	{INT,	PTR,	SIZE_T,	INT}}, /* 327 */
	{ 2,	"eventfd2"	,	{UINT,	INT}}, /* 328 */
	{ 1,	"epoll_create1"	,	{INT}}, /* 329 */
	{ 3,	"dup3"		,	{UINT,	UINT,	INT}}, /* 330 */
	{ 2,	"pipe2"		,	{INTTAB,	INT}}, /* 331 */
	{ 1,	"inotify_init1"	,	{INT}}, /* 332 */
	{ 5,	"preadv"	,	{ULONG,	PTR,	ULONG,	ULONG,	ULONG}}, /* 333 */
	{ 5,	"pwritev"	,	{ULONG,	PTR,	ULONG,	ULONG,	ULONG}}, /* 334 */
	{ 4,	"rt_tgsigqueueinfo",	{INT,	INT,	INT,	PTR}}, /* 335 */
	{ 5,	"perf_event_open",	{PTR,	INT,	INT,	INT,	ULONG}}, /* 336 */
	{ 5,	"recvmmsg"	,	{INT,	PTR,	UINT,	PTR,	PTR}}, /* 337 */
	{ 2,	"fanotify_init"	,{}}, /* 338 */
	{ 5,	"fanotify_mark"	,{}}, /* 339 */
	{ 4,	"prlimit64"	,{}}, /* 340 */
	{ 5,	"name_to_handle_at",{}}, /* 341 */
	{ 3,	"open_by_handle_at", {}}, /* 342 */
	{ 2,	"clock_adjtime"	,{}}, /* 343 */
	{ 1,	"syncfs"	,{}}, /* 344 */
	{ 4,	"sendmmsg"	,{}}, /* 345 */
	{ 2,	"setns"		,{}}, /* 346 */
	{ 6,	"process_vm_readv"	,{}}, /* 347 */
	{ 6,	"process_vm_writev"	,{}}, /* 348 */
	{ 5,	"kcmp"		,{}}, /* 349 */
	{ 3,	"finit_module"	,{}}, /* 350 */
	{ 5,	NULL		,{}}, /* 351 */
	{ 5,	NULL		,{}}, /* 352 */
	{ 5,	NULL		,{}}, /* 353 */
	{ 5,	NULL		,{}}, /* 354 */
	{ 5,	NULL		,{}}, /* 355 */
	{ 5,	NULL		,{}}, /* 356 */
	{ 5,	NULL		,{}}, /* 357 */
	{ 5,	NULL		,{}}, /* 358 */
	{ 5,	NULL		,{}}, /* 359 */
	{ 5,	NULL		,{}}, /* 360 */
	{ 5,	NULL		,{}}, /* 361 */
	{ 5,	NULL		,{}}, /* 362 */
	{ 5,	NULL		,{}}, /* 363 */
	{ 5,	NULL		,{}}, /* 364 */
	{ 5,	NULL		,{}}, /* 365 */
	{ 5,	NULL		,{}}, /* 366 */
	{ 5,	NULL		,{}}, /* 367 */
	{ 5,	NULL		,{}}, /* 368 */
	{ 5,	NULL		,{}}, /* 369 */
	{ 5,	NULL		,{}}, /* 370 */
	{ 5,	NULL		,{}}, /* 371 */
	{ 5,	NULL		,{}}, /* 372 */
	{ 5,	NULL		,{}}, /* 373 */
	{ 5,	NULL		,{}}, /* 374 */
	{ 5,	NULL		,{}}, /* 375 */
	{ 5,	NULL		,{}}, /* 376 */
	{ 5,	NULL		,{}}, /* 377 */
	{ 5,	NULL		,{}}, /* 378 */
	{ 5,	NULL		,{}}, /* 379 */
	{ 5,	NULL		,{}}, /* 380 */
	{ 5,	NULL		,{}}, /* 381 */
	{ 5,	NULL		,{}}, /* 382 */
	{ 5,	NULL		,{}}, /* 383 */
	{ 5,	NULL		,{}}, /* 384 */
	{ 5,	NULL		,{}}, /* 385 */
	{ 5,	NULL		,{}}, /* 386 */
	{ 5,	NULL		,{}}, /* 387 */
	{ 5,	NULL		,{}}, /* 388 */
	{ 5,	NULL		,{}}, /* 389 */
	{ 5,	NULL		,{}}, /* 390 */
	{ 5,	NULL		,{}}, /* 391 */
	{ 5,	NULL		,{}}, /* 392 */
	{ 5,	NULL		,{}}, /* 393 */
	{ 5,	NULL		,{}}, /* 394 */
	{ 5,	NULL		,{}}, /* 395 */
	{ 5,	NULL		,{}}, /* 396 */
	{ 5,	NULL		,{}}, /* 397 */
	{ 5,	NULL		,{}}, /* 398 */
	{ 5,	NULL		,{}}, /* 399 */
	{ 6,	"socket_subcall",{}}, /* 400 */
	{ 3,	"socket"	,{}}, /* 401 */
	{ 3,	"bind"		,{}}, /* 402 */
	{ 3,	"connect"	,{}}, /* 403 */
	{ 2,	"listen"	,{}}, /* 404 */
	{ 3,	"accept"	,{}}, /* 405 */
	{ 3,	"getsockname"	,{}}, /* 406 */
	{ 3,	"getpeername"	,{}}, /* 407 */
	{ 4,	"socketpair"	,{}}, /* 408 */
	{ 4,	"send"		,{}}, /* 409 */
	{ 4,	"recv"		,{}}, /* 410 */
	{ 6,	"sendto"	,{}}, /* 411 */
	{ 6,	"recvfrom"	,{}}, /* 412 */
	{ 2,	"shutdown"	,{}}, /* 413 */
	{ 5,	"setsockopt"	,{}}, /* 414 */
	{ 5,	"getsockopt"	,{}}, /* 415 */
	{ 3,	"sendmsg"	,{}}, /* 416 */
	{ 3,	"recvmsg"	,{}}, /* 417 */
	{ 4,	"accept4"	,{}}, /* 418 */
	{ 5,	"recvmmsg"	,{}}, /* 419 */
	{ 4,	"ipc_subcall"	,{}}, /* 420 */
	{ 4,	"semop"		,{}}, /* 421 */
	{ 4,	"semget"	,{}}, /* 422 */
	{ 4,	"semctl"	,{}}, /* 423 */
	{ 5,	"semtimedop"	,{}}, /* 424 */
	{ 4,	"ipc_subcall"	,{}}, /* 425 */
	{ 4,	"ipc_subcall"	,{}}, /* 426 */
	{ 4,	"ipc_subcall"	,{}}, /* 427 */
	{ 4,	"ipc_subcall"	,{}}, /* 428 */
	{ 4,	"ipc_subcall"	,{}}, /* 429 */
	{ 4,	"ipc_subcall"	,{}}, /* 430 */
	{ 4,	"msgsnd"	,{}}, /* 431 */
	{ 4,	"msgrcv"	,{}}, /* 432 */
	{ 4,	"msgget"	,{}}, /* 433 */
	{ 4,	"msgctl"	,{}}, /* 434 */
	{ 4,	"ipc_subcall"	,{}}, /* 435 */
	{ 4,	"ipc_subcall"	,{}}, /* 436 */
	{ 4,	"ipc_subcall"	,{}}, /* 437 */
	{ 4,	"ipc_subcall"	,{}}, /* 438 */
	{ 4,	"ipc_subcall"	,{}}, /* 439 */
	{ 4,	"ipc_subcall"	,{}}, /* 440 */
	{ 4,	"shmat"		,{}}, /* 441 */
	{ 4,	"shmdt"		,{}}, /* 442 */
	{ 4,	"shmget"	,{}}, /* 443 */
	{ 4,	"shmctl"	,{}}, /* 444 */
	{ 0,	NULL		,{}}
};

#define putstr(type, var) ({ \
	unsigned long	s_putstr; \
	size_t		j_putstr; \
	int		k_putstr; \
	\
	if ((s_putstr = ptrace(PTRACE_PEEKTEXT,pid, args[i], NULL)) && \
		(isprint(((char *)&s_putstr)[0]) || isspace(((char *)&s_putstr)[0]))) \
	{ \
		j_putstr = 0; \
		k_putstr = 0; \
		while ((s_putstr != 0 && j_putstr < 32)) \
		{ \
			while (k_putstr < 4 && (isprint(((char *)&s_putstr)[k_putstr]) || \
				isspace(((char *)&s_putstr)[k_putstr])) && \
				((j_putstr < 32 && type != STRSTOP) || \
				j_putstr < (size_t)args[i + 1])) \
			{ \
				str[j_putstr] = ((char *)&s_putstr)[k_putstr]; \
				j_putstr++; \
				k_putstr++; \
			} \
			if (k_putstr < 4 || j_putstr == 32 || \
				(type == STRSTOP && j_putstr == (size_t)args[i + 1])) \
			{ \
				str[j_putstr] = '\0'; \
				j_putstr = epur_str(str); \
				printf("\"%s\"", str); \
				if (j_putstr == 32) \
					printf("..."); \
				break ; \
			} \
			else \
			{ \
				s_putstr = 0; \
				s_putstr = ptrace(PTRACE_PEEKTEXT,pid,args[i] + j_putstr, NULL); \
			} \
			k_putstr = 0; \
		} \
		if (s_putstr == 0 && (k_putstr == 0 || k_putstr == 4) && j_putstr) \
		{ \
				str[j_putstr] = '\0'; \
				j_putstr = epur_str(str); \
				printf("\"%s\"", str); \
				s_putstr = 1; \
		} \
	} \
})

#define putint(type, var) ({ \
	switch (type) \
	{ \
		case CHAR: \
			printf("[%hhd]", (char)var);\
			break ; \
		case SHORT: \
			printf("[%hd]", (short)var);\
			break ; \
		case SIZE_T: \
			printf("[%zu]", (size_t)var);\
			break ;\
		case LONG: \
			printf("[%ld]", (long)var);\
			break ; \
		case ULONG: \
			printf("[%lu]", (long)var);\
			break ; \
		case LONGLONG: \
			printf("[%lld]", (long long)var);\
			break ; \
		case INT: \
			printf("[%d]", (int)var); \
			break ; \
		case UINT: \
			printf("[%u]", (int)var); \
			break ; \
		default: \
			var == 0 ? printf("NULL") : printf("%p", (void *)var); \
			printf("[%d]", (int)var); \
			 break ; \
	} \
})
#endif
