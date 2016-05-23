/*
** adbtelnd.c
* Telnet daemon for permissions persistance
* Phase 1 - daemonize localhost:6502 to spawn bash
*/
#define DEBUG 1
#undef DEBUG
#define NO_RAW
#define SHELL_BASH
#define SHELL_MKSH
#undef SHELL_MKSH

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

#define __USE_GNU 1
#define __USE_XOPEN 1
#include <stdlib.h>
#undef __USE_GNU
#undef __USE_XOPEN

#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <termios.h>
#ifdef DEBUG
# define TELCMDS
# define TELOPTS
#endif /* ifdef DEBUG */
#include <arpa/telnet.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/if.h>

#define BUFSIZE 4000

#define MIN(a, b) ((a) > (b) ? (b) : (a))


int telnet_timeout = 300; // 300 is 5 minutes
#ifdef SHELL_BASH
static char *loginpath   = "/data/local/tmp/xbin/bash";
static char *argv_init[] = {
  "/data/local/tmp/xbin/bash",
  "-",
  NULL
};

// single quote is 047 octal
static char *env[] = {
  "HOME=/data/local/tmp/etc",
  "LD_LIBRARY_PATH=/data/local/tmp/lib",
  "BASH_DIRTRIM=2",
  "PATH=/data/local/tmp/xbin:/system/bin:/system/xbin",
  "FIFOS=/data/data/jackpal.androidterm/app_fifos",
  "TERM=screen-256color",
  "TERMINFO=/data/local/tmp/lib/terminfo",
  "TMPDIR=/data/local/tmp/tmp",
  "TMOUT=0",
  "SPELL=\"myspell american-english\"",
  "LS_COLORS=\047no=00;38;5;244:rs=0:di=00;38;5;33:ln=00;38;5;37:mh=00:pi=48;5;230;38;5;136;01:so=48;5;230;38;5;136;01:do=48;5;230;38;5;136;01:bd=48;5;230;38;5;244;01:cd=48;5;230;38;5;244;01:or=48;5;235;38;5;160:su=48;5;160;38;5;230:sg=48;5;136;38;5;230:ca=30;41:tw=48;5;64;38;5;230:ow=48;5;235;38;5;33:st=48;5;33;38;5;230:ex=00;38;5;64:*.tar=00;38;5;61:*.tgz=00;38;5;61:*.arj=00;38;5;61:*.taz=00;38;5;61:*.lzh=00;38;5;61:*.lzma=00;38;5;61:*.tlz=00;38;5;61:*.txz=00;38;5;61:*.zip=00;38;5;61:*.z=00;38;5;61:*.Z=00;38;5;61:*.dz=00;38;5;61:*.gz=00;38;5;61:*.lz=00;38;5;61:*.xz=00;38;5;61:*.bz2=00;38;5;61:*.bz=00;38;5;61:*.tbz=00;38;5;61:*.tbz2=00;38;5;61:*.tz=00;38;5;61:*.deb=00;38;5;61:*.rpm=00;38;5;61:*.jar=00;38;5;61:*.rar=00;38;5;61:*.ace=00;38;5;61:*.zoo=00;38;5;61:*.cpio=00;38;5;61:*.7z=00;38;5;61:*.rz=00;38;5;61:*.apk=00;38;5;61:*.raw=00;38;5;61:*.jpg=00;38;5;136:*.jpeg=00;38;5;136:*.gif=00;38;5;136:*.bmp=00;38;5;136:*.pbm=00;38;5;136:*.pgm=00;38;5;136:*.ppm=00;38;5;136:*.tga=00;38;5;136:*.xbm=00;38;5;136:*.xpm=00;38;5;136:*.tif=00;38;5;136:*.tiff=00;38;5;136:*.png=00;38;5;136:*.svg=00;38;5;136:*.svgz=00;38;5;136:*.mng=00;38;5;136:*.pcx=00;38;5;136:*.dl=00;38;5;136:*.xcf=00;38;5;136:*.xwd=00;38;5;136:*.yuv=00;38;5;136:*.cgm=00;38;5;136:*.emf=00;38;5;136:*.eps=00;38;5;136:*.ico=00;38;5;136:*.tex=00;38;5;245:*.rdf=00;38;5;245:*.xml=00;38;5;245:*Makefile=00;38;5;245:*build.xml=00;38;5;245:*rc=00;38;5;245:*1=00;38;5;245:*.nfo=00;38;5;245:*README=00;38;5;245:*README.txt=00;38;5;245:*readme.txt=00;38;5;245:*.md=00;38;5;245:*.lua=90:*.ini=00;38;5;245:*.yml=00;38;5;245:*.cfg=00;38;5;245:*.conf=00;38;5;245:*.h=00;38;5;245:*.hpp=00;38;5;245:*.c=00;38;5;245:*.cpp=00;38;5;245:*.cxx=00;38;5;245:*.cc=00;38;5;245:*.objc=00;38;5;245:*.sqlite=00;38;5;245:*.go=00;38;5;245:*.sql=00;38;5;245:*.csv=00;38;5;245:*.log=00;38;5;240:*.bak=00;38;5;240:*.aux=00;38;5;240:*.out=00;38;5;240:*.toc=00;38;5;240:*.bbl=00;38;5;240:*.blg=00;38;5;240:*~=00;38;5;240:*#=00;38;5;240:*.tmp=00;38;5;240:*.o=00;38;5;240:*.pyc=00;38;5;240:*.class=00;38;5;240:*.cache=00;38;5;240:*.aac=00;38;5;166:*.au=00;38;5;166:*.flac=00;38;5;166:*.mid=00;38;5;166:*.midi=00;38;5;166:*.mka=00;38;5;166:*.mp3=00;38;5;166:*.mpc=00;38;5;166:*.ogg=00;38;5;166:*.opus=00;38;5;166:*.ra=00;38;5;166:*.wav=00;38;5;166:*.m4a=00;38;5;166:*.oga=00;38;5;166:*.spx=00;38;5;166:*.xspf=00;38;5;166:*.mov=00;38;5;166:*.MOV=00;38;5;166:*.mpg=00;38;5;166:*.mpeg=00;38;5;166:*.m2v=00;38;5;166:*.mkv=00;38;5;166:*.ogm=00;38;5;166:*.mp4=00;38;5;166:*.m4v=00;38;5;166:*.mp4v=00;38;5;166:*.vob=00;38;5;166:*.qt=00;38;5;166:*.nuv=00;38;5;166:*.wmv=00;38;5;166:*.asf=00;38;5;166:*.rm=00;38;5;166:*.rmvb=00;38;5;166:*.flc=00;38;5;166:*.avi=00;38;5;166:*.fli=00;38;5;166:*.flv=00;38;5;166:*.gl=00;38;5;166:*.m2ts=00;38;5;166:*.divx=00;38;5;166:*.webm=00;38;5;166:*.axv=00;38;5;166:*.anx=00;38;5;166:*.ogv=00;38;5;166:*.ogx=00;38;5;166:\047",
  "alias ls=\047ls --color\047",
  NULL
};
#else /* ifdef SHELL_BASH */

/** Default mksh **/
static char *loginpath   = "/system/bin/mksh";
static char *argv_init[] = {
  "/system/bin/sh",
  "-",
  NULL
};

/* not allowed to set PS1 on Android mksh */
/* so we will configure PS0 for later application */
static char *env[] = {
  "HOME=/data/local/tmp/etc",
  "PATH=/data/local/tmp/xbin:/system/bin:/system/xbin",
  "LD_LIBRARY_PATH=/data/local/tmp/lib",
  "BASH_DIRTRIM=2",
  "FIFOS=/data/data/jackpal.androidterm/app_etc/app_fifos",
  "SHELL=/system.bin/mksh",
  "TERM=screen-256color",
  "TERMINFO=/data/local/tmp/xbin/terminfo",
  "TMPDIR=/data/local/tmp/tmp",
  "TMOUT=0",
  "SPELL=\"myspell american-english\"",
  "PS0=$\047\\a\\r\\a\\e[1;34m\\a ┌─| \\a\\e[36m\\a${USER:=$(ulimit -c 0; id -un 2>/dev/null || echo \\?)}@${HOSTNAME%%.*}\\a\\e[34m\\a |──| \\a\\e[0;33m\\a$(local d=${PWD:-?} p=~; [[ $p = ?(*/) ]] || d=${d/#$p/~}; print -nr -- \"$d\")\\a\\e[1;34m\\a |\\n └─| \\a\\e[32m\\a$(date +%H:%M)\\a\\e[34m\\a |─>> \\a\\e[0m\\a \047",
  NULL
};
#endif /* ifdef SHELL_BASH */

struct tsession {
  struct tsession *next;
  int              sockfd, ptyfd;
  int              shell_pid;

  /* two circular buffers */
  unsigned char *buf1, *buf2;
  int            rdidx1, wridx1, size1;
  int            rdidx2, wridx2, size2;
};

#ifdef DEBUG
# define DEBUG_OUT(...) fprintf(stderr, __VA_ARGS__)
#else /* ifdef DEBUG */
# define DEBUG_OUT(...)
#endif /* ifdef DEBUG */
static int maxfd;
static struct tsession *sessions;

void show_usage(void)
{
  printf("Usage: telnetd [-p port] [-l loginprogram] [-n] [-t timeout]\n");
  printf("\n");
  printf("   -p port          specify the tcp port to connect to\n");
  printf("   -l loginprogram  program started by the server\n");
  printf("   -t timeout       time in minutes before abandon idle connection\n");
  printf("   -n               no, dont daemonize\n");
  printf(
    "Note: only listens to localhost, default to timeout never, port 6502, daemonize\n");
  printf("\n");
  exit(1);
}

void perror_msg_and_die(char *text)
{
  fprintf(stderr, "%s\n", text);
  exit(1);
}

static char *
remove_iacs(unsigned char *bf, int len, int *processed, int *num_totty) {
  unsigned char *ptr   = bf;
  unsigned char *totty = bf;
  unsigned char *end   = bf + len;

  while (ptr < end) {
    if (*ptr != IAC) {
      *totty++ = *ptr++;
    }
    else {
      if ((ptr + 2) < end) {
        DEBUG_OUT("Ignoring IAC 0x%02x, %s, %s\n", *ptr, TELCMD(
                    *(ptr + 1)), TELOPT(*(ptr + 2)));
        ptr += 3;
      } else {
        break;
      }
    }
  }

  *processed = ptr - bf;
  *num_totty = totty - bf;

  return memmove(ptr - *num_totty, bf, *num_totty);
}

static int subst_crlf_cr(unsigned char *bf, int len)
{
  unsigned char *ptr = bf;
  unsigned char *end = bf + len;
  int cr_found       = 0;
  int lf_removed     = 0;

  while (ptr < end)
  {
    if (*ptr == '\r')
    {
      cr_found = 1;
    }
    else
    {
      if ((*ptr == '\n') && (cr_found))
      {
        memmove(ptr, ptr + 1, end - (ptr + 1));
        lf_removed++;
        end--;
        ptr--;
      }
      cr_found = 0;
    }
    ptr++;
  }
  return lf_removed;
}

struct termios termbuf, original_termbuf;

void tty_raw(int ttyfd)
{
  struct termios raw;

  raw          = termbuf;
  raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
  raw.c_oflag &= ~(OPOST);
  raw.c_cflag |= (CS8);
  raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

  raw.c_cc[VMIN] = 5; raw.c_cc[VTIME] = 8;

  raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0;
  raw.c_cc[VMIN] = 2; raw.c_cc[VTIME] = 0;
  raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 8;

  if (tcsetattr(ttyfd, TCSAFLUSH, &raw) < 0) perror_msg_and_die(
      "fatal: no raw mode");
}

static struct tsession *
make_new_session(int sockfd)
{
  int pty, pid, ptmx_fd, t1, t2;
  static char tty_name[32];
  struct tsession *ts = (struct tsession *)malloc(sizeof(struct tsession));
  t1 =0;
  t2 =0;

  ts->buf1 = (unsigned char *)malloc(BUFSIZE);
  ts->buf2 = (unsigned char *)malloc(BUFSIZE);

  ts->sockfd = sockfd;

  ts->rdidx1 = ts->wridx1 = ts->size1 = 0;
  ts->rdidx2 = ts->wridx2 = ts->size2 = 0;

  /*
  ** Aarons additions
  */

  /* Open the master device. */
  ptmx_fd = open("/dev/ptmx", O_RDWR);

  if (grantpt(ptmx_fd) || unlockpt(ptmx_fd)) {
    //return -1;
    return (void *)0;
  }

    strcpy(tty_name, ptsname(ptmx_fd));

  /*
  ** Aarons additions
  */

  // pty = getpty(tty_name);
  pty = ptmx_fd;

  if (pty < 0) {
    fprintf(stderr, "All network ports in use!\n");
    return 0;
  }

  if (pty > maxfd) maxfd = pty;

  ts->ptyfd = pty;


  if ((pid = fork()) < 0) {
    perror("fork");
  }

  if (pid == 0) {
    int i, t;

    for (i = 0; i <= maxfd; i++) close(i);

    if (setsid() < 0) perror_msg_and_die("setsid");

    t = open(tty_name, O_RDWR | O_NOCTTY); // modify to make ctrl+c possible

    if (t < 0) perror_msg_and_die("Could not open tty");

    t1 = dup(0);
    t2 = dup(1);

    tcsetpgrp(0, getpid());

    /* modify to make ctrl+c possible*/
    if (ioctl(t, TIOCSCTTY, NULL)) {
      perror_msg_and_die("could not set controlling tty");
    }

#ifdef NO_RAW
    tcgetattr(t, &original_termbuf);
    tcgetattr(t, &termbuf);
    termbuf.c_lflag |= ECHO;
    termbuf.c_oflag |= ONLCR | XTABS;
    termbuf.c_iflag |= ICRNL;
    termbuf.c_iflag &= ~IXOFF;

    termbuf.c_lflag &= ~ICANON;
    tcsetattr(t, TCSANOW, &termbuf);
#else /* ifdef NO_RAW */
    tcgetattr(t, &original_termbuf);
    tcgetattr(t, &termbuf);
    tty_raw(t);
    tcgetattr(t, &termbuf);
    termbuf.c_lflag |= ECHO;
    termbuf.c_oflag |= OPOST;
    termbuf.c_oflag |= ONLCR; // | XTABS;
    tcsetattr(t, TCSANOW, &termbuf);
#endif /* NO_RAW */

    DEBUG_OUT("stdin, stdout, stderr: %d %d %d\n", t, t1, t2);
    execle(loginpath, (char *)argv_init, NULL, env);
    perror_msg_and_die("execv");
  }

  ts->shell_pid = pid;

  return ts;
}

static void
free_session(struct tsession *ts)
{
  struct tsession *t = sessions;

  if (t == ts) sessions = ts->next;
  else {
    while (t->next != ts) t = t->next;
    t->next = ts->next;
  }

  free(ts->buf1);
  free(ts->buf2);

  kill(ts->shell_pid, SIGKILL);

  wait4(ts->shell_pid, NULL, 0, NULL);

  close(ts->ptyfd);
  close(ts->sockfd);

  if ((ts->ptyfd == maxfd) || (ts->sockfd == maxfd)) maxfd--;

  if ((ts->ptyfd == maxfd) || (ts->sockfd == maxfd)) maxfd--;

  free(ts);
}

int main(int argc, char **argv)
{
  struct sockaddr_in sa;
  int master_fd;
  fd_set rdfdset, wrfdset;
  int    selret;
  int    on      = 1;
  int    portnbr = 6502;
  int    c, ii;
  int    daemonize = 1;

  for (;;) {
    c = getopt(argc, argv, "p:l:hdt:");

    if (c == EOF) break;

    switch (c) {
    case 'p':
      portnbr = atoi(optarg);
      break;

    case 'l':
      loginpath = strdup(optarg);
      break;

    case 'n':
      daemonize = 0;
      break;

    case 't':
      telnet_timeout = atoi(optarg) * 60;
      break;

    case 'h':
    default:
      show_usage();
      exit(1);
    }
  }

  if (!loginpath) {
    loginpath = "/bin/login";

    if (access(loginpath, X_OK) < 0)
#ifdef __ANDROID__
      loginpath = "/data/local/tmp/xbin/bash";
#else /* ifdef __ANDROID__ */ 
      //
      loginpath = "/bin/sh";
#endif /* ifdef __ANDROID__ */
  }

  if (access(loginpath, X_OK) < 0) {
    fprintf(stderr, "\"%s\"", loginpath);
    perror_msg_and_die("invalid executable!\n");
  }

  printf("telnetd: starting\n");
  printf("  port: %i; login program: %s\n", portnbr, loginpath);

  argv_init[0] = loginpath;
  sessions     = 0;

  master_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (master_fd < 0) {
    perror("socket");
    return 1;
  }
  (void)setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  memset((void *)&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // listen on 127.0.0.1 (lo)
  sa.sin_port        = htons(portnbr);

  if (bind(master_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    return 1;
  }

  if (listen(master_fd, 1) < 0) {
    perror("listen");
    return 1;
  }

  if (daemonize)
  {
    DEBUG_OUT("daemonizing\n");

    if (daemon(0, 1) < 0) perror_msg_and_die("daemon");
  }

  maxfd = master_fd;

  do {
    struct tsession *ts;
    struct timeval   timeout;

    FD_ZERO(&rdfdset);
    FD_ZERO(&wrfdset);

    timeout.tv_sec  = telnet_timeout;
    timeout.tv_usec = 0;

        FD_SET(master_fd, &rdfdset);

    ts = sessions;

    while (ts) {
      if (ts->size1 > 0) {
        FD_SET(ts->ptyfd, &wrfdset); /* can write to pty */
      }

      if (ts->size1 < BUFSIZE) {
        FD_SET(ts->sockfd, &rdfdset); /* can read from socket */
      }

      if (ts->size2 > 0) {
        FD_SET(ts->sockfd, &wrfdset); /* can write to socket */
      }

      if (ts->size2 < BUFSIZE) {
        FD_SET(ts->ptyfd, &rdfdset); /* can read from pty */
      }
      ts = ts->next;
    }

    if (telnet_timeout) {
      selret = select(maxfd + 1, &rdfdset, &wrfdset, 0, &timeout);
    }
    else {
      selret = select(maxfd + 1, &rdfdset, &wrfdset, 0, NULL);
    }


    if (!selret) {
      ts = sessions;

      while (ts) {
        free_session(ts);
        ts = ts->next;
      }
      continue;
    }

    /* First check for and accept new sessions.  */
    if (FD_ISSET(master_fd, &rdfdset)) {
      int fd, salen;

      salen = sizeof(sa);

      if ((fd = accept(master_fd, (struct sockaddr *)&sa,
                       &salen)) < 0) {
        continue;
      } else {
        struct tsession *new_ts = make_new_session(fd);

        if (new_ts) {
          new_ts->next = sessions;
          sessions     = new_ts;

          if (fd > maxfd) maxfd = fd;
        } else {
          close(fd);
        }
      }
    }

    ts = sessions;

    while (ts) {                        /* For all sessions...  */
      int maxlen, w, r;
      struct tsession *next = ts->next; /* in case we free ts. */

      if (ts->size1 && FD_ISSET(ts->ptyfd, &wrfdset)) {
        int   processed, num_totty, num_lfs;
        char *ptr;

        maxlen = MIN(BUFSIZE - ts->wridx1,
                     ts->size1);
        ptr = remove_iacs(ts->buf1 + ts->wridx1, maxlen,
                          &processed, &num_totty);

        ts->wridx1 += processed - num_totty;
        ts->size1  -= processed - num_totty;

        num_lfs    = subst_crlf_cr(ts->buf1 + ts->wridx1, maxlen);
        ts->size1 -= num_lfs;
        num_totty -= num_lfs;

        w = write(ts->ptyfd, ptr, num_totty);

        if (w < 0) {
          perror("write");
          free_session(ts);
          ts = next;
          continue;
        }
        ts->wridx1 += w;
        ts->size1  -= w;

        if (ts->wridx1 == BUFSIZE) ts->wridx1 = 0;
      }

      if (ts->size2 && FD_ISSET(ts->sockfd, &wrfdset)) {
        maxlen = MIN(BUFSIZE - ts->wridx2,
                     ts->size2);
        w = write(ts->sockfd, ts->buf2 + ts->wridx2, maxlen);

        if (w < 0) {
          perror("write");
          free_session(ts);
          ts = next;
          continue;
        }
        ts->wridx2 += w;
        ts->size2  -= w;

        if (ts->wridx2 == BUFSIZE) ts->wridx2 = 0;
      }

      if ((ts->size1 < BUFSIZE) && FD_ISSET(ts->sockfd, &rdfdset)) {
        /* Read from socket to buffer 1. */
        maxlen = MIN(BUFSIZE - ts->rdidx1,
                     BUFSIZE - ts->size1);
        r = read(ts->sockfd, ts->buf1 + ts->rdidx1, maxlen);

        if (!r || ((r < 0) && (errno != EINTR))) {
          free_session(ts);
          ts = next;
          continue;
        }

        if (!*(ts->buf1 + ts->rdidx1 + r - 1)) {
          r--;

          if (!r) continue;
        }
        ts->rdidx1 += r;
        ts->size1  += r;

        if (ts->rdidx1 == BUFSIZE) ts->rdidx1 = 0;
      }

      if ((ts->size2 < BUFSIZE) && FD_ISSET(ts->ptyfd, &rdfdset)) {
        /* Read from pty to buffer 2.  */
        maxlen = MIN(BUFSIZE - ts->rdidx2,
                     BUFSIZE - ts->size2);
        r = read(ts->ptyfd, ts->buf2 + ts->rdidx2, maxlen);

        if (!r || ((r < 0) && (errno != EINTR))) {
          free_session(ts);
          ts = next;
          continue;
        }

        for (ii = 0; ii < r; ii++)
          if (*(ts->buf2 + ts->rdidx2 + ii) == 3) fprintf(
              stderr,
              "found <CTRL>-<C> in data!\n");
        ts->rdidx2 += r;
        ts->size2  += r;

        if (ts->rdidx2 == BUFSIZE) ts->rdidx2 = 0;
      }

      if (ts->size1 == 0) {
        ts->rdidx1 = 0;
        ts->wridx1 = 0;
      }

      if (ts->size2 == 0) {
        ts->rdidx2 = 0;
        ts->wridx2 = 0;
      }
      ts = next;
    }
  } while (1);

  return 0;
}

