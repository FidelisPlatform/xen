/*\
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Xen Console Daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
\*/

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <termios.h>
#include <signal.h>
#include <getopt.h>
#include <sys/select.h>
#include <err.h>
#include <string.h>
#ifdef __sun__
#include <sys/stropts.h>
#endif

#include <xenstore.h>
#include "xenctrl.h"

#define DEFAULT_ESCAPE_CHARACTER 0x1d

static volatile sig_atomic_t received_signal = 0;
static char lockfile[sizeof (XEN_LOCK_DIR "/xenconsole.") + 8] = { 0 };
static int lockfd = -1;

static void sighandler(int signum)
{
	received_signal = 1;
}

static bool write_sync(int fd, const void *data, size_t size)
{
	size_t offset = 0;
	ssize_t len;

	while (offset < size) {
		len = write(fd, data + offset, size - offset);
		if (len < 1) {
			return false;
		}
		offset += len;
	}

	return true;
}

static void usage(const char *program) {
	printf("Usage: %s [OPTION] DOMID\n"
	       "Attaches to a virtual domain console\n"
	       "\n"
	       "  -h, --help       display this help and exit\n"
	       "  -n, --num N      use console number N\n"
	       "  --type TYPE      console type. must be 'pv', 'serial' or 'vuart'\n"
	       "  --start-notify-fd N file descriptor used to notify parent\n"
	       "  --escape E       escape sequence to exit console\n"
	       , program);
}

#ifdef	__sun__
void cfmakeraw(struct termios *termios_p)
{
	termios_p->c_iflag &=
	    ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	termios_p->c_oflag &= ~OPOST;
	termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	termios_p->c_cflag &= ~(CSIZE|PARENB);
	termios_p->c_cflag |= CS8;

	termios_p->c_cc[VMIN] = 0;
	termios_p->c_cc[VTIME] = 0;
}
#endif

static int get_pty_fd(struct xs_handle *xs, char *path, int seconds)
/* Check for a pty in xenstore, open it and return its fd.
 * Assumes there is already a watch set in the store for this path. */
{
	struct timeval tv;
	fd_set watch_fdset;
	int xs_fd = xs_fileno(xs), pty_fd = -1;
	time_t start, now;
	unsigned int len = 0;
	char *pty_path, **watch_paths;

	start = now = time(NULL);
	do {
		tv.tv_usec = 0;
		tv.tv_sec = (start + seconds) - now;
		FD_ZERO(&watch_fdset);
		FD_SET(xs_fd, &watch_fdset);
		if (select(xs_fd + 1, &watch_fdset, NULL, NULL, &tv)) {
			/* Read the watch to drain the buffer */
			watch_paths = xs_read_watch(xs, &len);
			free(watch_paths);
			/* We only watch for one thing, so no need to 
			 * disambiguate: just read the pty path */
			pty_path = xs_read(xs, XBT_NULL, path, &len);
			if (pty_path != NULL && pty_path[0] != '\0') {
				pty_fd = open(pty_path, O_RDWR | O_NOCTTY);
				if (pty_fd == -1)
					warn("Could not open tty `%s'", pty_path);
			}
			free(pty_path);
		}
	} while (pty_fd == -1 && (now = time(NULL)) < start + seconds);

#ifdef __sun__
	if (pty_fd != -1) {
		struct termios term;

		/*
		 * The pty may come from either xend (with pygrub) or
		 * xenconsoled.  It may have tty semantics set up, or not.
		 * While it isn't strictly necessary to have those
		 * semantics here, it is good to have a consistent
		 * state that is the same as under Linux.
		 *
		 * If tcgetattr fails, they have not been set up,
		 * so go ahead and set them up now, by pushing the
		 * ptem and ldterm streams modules.
		 */
		if (tcgetattr(pty_fd, &term) < 0) {
			ioctl(pty_fd, I_PUSH, "ptem");
			ioctl(pty_fd, I_PUSH, "ldterm");
		}
	}
#endif

	return pty_fd;
}


/* don't worry too much if setting terminal attributes fail */
static void init_term(int fd, struct termios *old)
{
	struct termios new_term;

	if (tcgetattr(fd, old) == -1)
		return;

	new_term = *old;
	cfmakeraw(&new_term);

	tcsetattr(fd, TCSANOW, &new_term);
}

static void restore_term(int fd, struct termios *old)
{
	tcsetattr(fd, TCSANOW, old);
}

static int console_loop(int fd, struct xs_handle *xs, char *pty_path,
			bool interactive, char escape_character)
{
	int ret, xs_fd = xs_fileno(xs), max_fd = -1;

	do {
		fd_set fds;

		FD_ZERO(&fds);
		if (interactive) {
			FD_SET(STDIN_FILENO, &fds);
			max_fd = STDIN_FILENO;
		}
		FD_SET(xs_fd, &fds);
		if (xs_fd > max_fd) max_fd = xs_fd;
		if (fd != -1) FD_SET(fd, &fds);
		if (fd > max_fd) max_fd = fd;

		ret = select(max_fd + 1, &fds, NULL, NULL, NULL);
		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return -1;
		}

		if (FD_ISSET(xs_fileno(xs), &fds)) {
			int newfd = get_pty_fd(xs, pty_path, 0);
			if (fd != -1)
				close(fd);
                        if (newfd == -1) 
				/* Console PTY has become invalid */
				return 0;
			fd = newfd;
			continue;
		}

		if (FD_ISSET(STDIN_FILENO, &fds)) {
			ssize_t len;
			char msg[60];

			len = read(STDIN_FILENO, msg, sizeof(msg));
			if (len == 1 && msg[0] == escape_character) {
				return 0;
			} 

			if (len == 0 || len == -1) {
				if (len == -1 &&
				    (errno == EINTR || errno == EAGAIN)) {
					continue;
				}
				return -1;
			}

			if (!write_sync(fd, msg, len)) {
				close(fd);
				fd = -1;
				continue;
			}
		}

		if (fd != -1 && FD_ISSET(fd, &fds)) {
			ssize_t len;
			char msg[512];

			len = read(fd, msg, sizeof(msg));
			if (len == 0 || len == -1) {
				if (len == -1 &&
				    (errno == EINTR || errno == EAGAIN)) {
					continue;
				}
				close(fd);
				fd = -1;
				continue;
			}

			if (!write_sync(STDOUT_FILENO, msg, len)) {
				perror("write() failed");
				return -1;
			}
		}
	} while (received_signal == 0);

	return 0;
}

typedef enum {
       CONSOLE_INVAL,
       CONSOLE_PV,
       CONSOLE_SERIAL,
       CONSOLE_VUART,
} console_type;

static struct termios stdin_old_attr;

static void restore_term_stdin(void)
{
	restore_term(STDIN_FILENO, &stdin_old_attr);
}

/* The following locking strategy is based on that from
 * libxl__domain_userdata_lock(), with the difference that we want to fail if we
 * cannot acquire the lock rather than wait indefinitely.
 */
static void console_lock(int domid)
{
	struct stat stab, fstab;
	int fd;

	snprintf(lockfile, sizeof lockfile, "%s%d", XEN_LOCK_DIR "/xenconsole.", domid);

	while (true) {
		fd = open(lockfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		if (fd < 0)
			err(errno, "Could not open %s", lockfile);

		while (flock(fd, LOCK_EX | LOCK_NB)) {
			if (errno == EINTR)
				continue;
			else
				err(errno, "Could not lock %s", lockfile);
		}
		if (fstat(fd, &fstab))
			err(errno, "Could not fstat %s", lockfile);
		if (stat(lockfile, &stab)) {
			if (errno != ENOENT)
				err(errno, "Could not stat %s", lockfile);
		} else {
			if (stab.st_dev == fstab.st_dev && stab.st_ino == fstab.st_ino)
				break;
		}

		close(fd);
	}

	lockfd = fd;
	return;
}

static void console_unlock(void)
{
	if (lockfile[0] && lockfd != -1) {
		unlink(lockfile);
		close(lockfd);
	}
}

int main(int argc, char **argv)
{
	struct termios attr;
	int domid;
	const char *sopt = "hn:";
	int ch;
	unsigned int num = 0;
	int opt_ind=0;
	int start_notify_fd = -1;
	struct option lopt[] = {
		{ "type",     1, 0, 't' },
		{ "num",     1, 0, 'n' },
		{ "help",    0, 0, 'h' },
		{ "start-notify-fd", 1, 0, 's' },
		{ "interactive", 0, 0, 'i' },
		{ "escape",  1, 0, 'e' },
		{ 0 },

	};
	char *dom_path = NULL, *path = NULL, *test = NULL;
	int spty, xsfd;
	struct xs_handle *xs;
	char *end;
	console_type type = CONSOLE_INVAL;
	bool interactive = 0;
	const char *console_names = "serial, pv, vuart";
	char escape_character = DEFAULT_ESCAPE_CHARACTER;

	while((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
		switch(ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'n':
			num = atoi(optarg);
			break;
		case 't':
			if (!strcmp(optarg, "serial"))
				type = CONSOLE_SERIAL;
			else if (!strcmp(optarg, "pv"))
				type = CONSOLE_PV;
			else if (!strcmp(optarg, "vuart"))
				type = CONSOLE_VUART;
			else {
				fprintf(stderr, "Invalid type argument\n");
				fprintf(stderr, "Console types supported are: %s\n",
					console_names);
				exit(EINVAL);
			}
			break;
		case 's':
			start_notify_fd = atoi(optarg);
			break;
		case 'i':
			interactive = 1;
			break;
		case 'e':
			if (optarg[0] == '^' && optarg[1] && optarg[2] == '\0')
				escape_character = optarg[1] & 0x1f;
			else if (optarg[0] && optarg[1] == '\0')
				escape_character = optarg[0];
			else {
				fprintf(stderr, "Invalid escape argument\n");
				exit(EINVAL);
			}
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			fprintf(stderr, "Try `%s --help' for more information.\n", 
					argv[0]);
			exit(EINVAL);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "DOMID should be specified\n");
		fprintf(stderr, "Try `%s --help' for more information.\n",
			argv[0]);
		exit(EINVAL);
	}
	domid = strtol(argv[optind], &end, 10);
	if (end && *end) {
		fprintf(stderr, "Invalid DOMID `%s'\n", argv[optind]);
		fprintf(stderr, "Try `%s --help' for more information.\n",
			argv[0]);
		exit(EINVAL);
	}

	xs = xs_open(0);
	if (xs == NULL) {
		err(errno, "Could not contact XenStore");
	}

	signal(SIGTERM, sighandler);

	dom_path = xs_get_domain_path(xs, domid);
	if (dom_path == NULL)
		err(errno, "xs_get_domain_path()");
	if (type == CONSOLE_INVAL) {
		xc_domaininfo_t xcinfo;
		xc_interface *xc_handle = xc_interface_open(0,0,0);
		if (xc_handle == NULL)
			err(errno, "Could not open xc interface");
		if (xc_domain_getinfo_single(xc_handle, domid, &xcinfo) < 0) {
			xc_interface_close(xc_handle);
			err(errno, "Failed to get domain information");
		}
		/* default to pv console for pv guests and serial for hvm guests */
		if (xcinfo.flags & XEN_DOMINF_hvm_guest)
			type = CONSOLE_SERIAL;
		else
			type = CONSOLE_PV;
		xc_interface_close(xc_handle);
	}
	path = malloc(strlen(dom_path) + strlen("/device/console/0/tty") + 5);
	if (path == NULL)
		err(ENOMEM, "malloc");
	if (type == CONSOLE_SERIAL) {
		snprintf(path, strlen(dom_path) + strlen("/serial/0/tty") + 5, "%s/serial/%d/tty", dom_path, num);
		test = xs_read(xs, XBT_NULL, path, NULL);
		free(test);
		if (test == NULL)
			type = CONSOLE_PV;
	}
	if (type == CONSOLE_PV) {

		if (num == 0)
			snprintf(path, strlen(dom_path) + strlen("/console/tty") + 1, "%s/console/tty", dom_path);
		else
			snprintf(path, strlen(dom_path) + strlen("/device/console/%d/tty") + 5, "%s/device/console/%d/tty", dom_path, num);
	}
	if (type == CONSOLE_VUART) {
		snprintf(path, strlen(dom_path) + strlen("/vuart/0/tty") + 1,
			 "%s/vuart/0/tty", dom_path);
	}

	/* FIXME consoled currently does not assume domain-0 doesn't have a
	   console which is good when we break domain-0 up.  To keep us
	   user friendly, we'll bail out here since no data will ever show
	   up on domain-0. */
	if (domid == 0) {
		fprintf(stderr, "Can't specify Domain-0\n");
		exit(EINVAL);
	}

	console_lock(domid);
	atexit(console_unlock);

	/* Set a watch on this domain's console pty */
	if (!xs_watch(xs, path, ""))
		err(errno, "Can't set watch for console pty");
	xsfd = xs_fileno(xs);

	/* Wait a little bit for tty to appear.  There is a race
	   condition that occurs after xend creates a domain.  This code
	   might be running before consoled has noticed the new domain
	   and setup a pty for it. */ 
        spty = get_pty_fd(xs, path, 5);
	if (spty == -1) {
		err(errno, "Could not read tty from store");
	}

	init_term(spty, &attr);
	if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
		interactive = 1;
		init_term(STDIN_FILENO, &stdin_old_attr);
		atexit(restore_term_stdin); /* if this fails, oh dear */
	}

	if (start_notify_fd != -1) {
		/* Write 0x00 to notify parent about client's readiness */
		static const char msg[] = { 0x00 };
		int r;

		do {
			r = write(start_notify_fd, msg, 1);
		} while ((r == -1 && errno == EINTR) || r == 0);

		if (r == -1)
			err(errno, "Could not notify parent with fd %d",
			    start_notify_fd);
		close(start_notify_fd);
	}

	console_loop(spty, xs, path, interactive, escape_character);

	free(path);
	free(dom_path);
	return 0;
 }
