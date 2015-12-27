/***
  This file is part of PulseAudio.

  Copyright 2004-2006 Lennart Poettering
  Copyright 2006 Pierre Ossman <ossman@cendio.se> for Cendio AB

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include <pulsecore/i18n.h>
#include <pulsecore/macro.h>
#include <pulsecore/log.h>

#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#if defined(__sun__) && defined(__SVR4)
#include <priv.h>
#endif

#include "caps.h"

/* Glibc <= 2.2 has broken unistd.h */
#if defined(__linux__) && (__GLIBC__ <= 2 && __GLIBC_MINOR__ <= 2)
int setresgid(gid_t r, gid_t e, gid_t s);
int setresuid(uid_t r, uid_t e, uid_t s);
#endif

/* Drop root rights when called SUID root */
void pa_drop_root(void) {

#ifdef HAVE_GETUID
    uid_t uid;
    gid_t gid;

    pa_log_debug("Cleaning up privileges.");
    uid = getuid();
    gid = getgid();

#if defined(HAVE_SETRESUID)
    pa_assert_se(setresuid(uid, uid, uid) >= 0);
    pa_assert_se(setresgid(gid, gid, gid) >= 0);
#elif defined(HAVE_SETREUID)
    pa_assert_se(setreuid(uid, uid) >= 0);
    pa_assert_se(setregid(gid, gid) >= 0);
#else
    pa_assert_se(setuid(uid) >= 0);
    pa_assert_se(seteuid(uid) >= 0);
    pa_assert_se(setgid(gid) >= 0);
    pa_assert_se(setegid(gid) >= 0);
#endif

    pa_assert_se(getuid() == uid);
    pa_assert_se(geteuid() == uid);
    pa_assert_se(getgid() == gid);
    pa_assert_se(getegid() == gid);

    if (uid != 0)
        pa_drop_caps();
#endif
}

void pa_drop_caps(void) {
#ifdef HAVE_SYS_CAPABILITY_H
#if defined(__linux__)
    cap_t caps;
    pa_assert_se(caps = cap_init());
    pa_assert_se(cap_clear(caps) == 0);
    pa_assert_se(cap_set_proc(caps) == 0);
    pa_assert_se(cap_free(caps) == 0);
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    /* FreeBSD doesn't have this functionality, even though sys/capability.h is
     * available. See https://bugs.freedesktop.org/show_bug.cgi?id=72580 */
    pa_log_warn("FreeBSD cannot drop extra capabilities, implementation needed.");
#else
#error "Don't know how to do capabilities on your system.  Please send a patch."
#endif /* __linux__ */
#else /* HAVE_SYS_CAPABILITY_H */
#if defined(__sun__) && defined(__SVR4)
    priv_set_t *sp;
    /* Set basic privileges */
    pa_assert_se(sp = priv_str_to_set("basic", ",", NULL));
    //pa_assert_se(sp = priv_allocset());
    //priv_emptyset(sp);
    //priv_addset(sp, PRIV_FILE_LINK_ANY);
    //priv_addset(sp, PRIV_FILE_READ);
    //priv_addset(sp, PRIV_FILE_WRITE);
    //priv_addset(sp, PRIV_NET_ACCESS);
    //priv_addset(sp, PRIV_PROC_FORK);
    //priv_addset(sp, PRIV_PROC_INFO);
    //priv_addset(sp, PRIV_PROC_SESSION);
    priv_addset(sp, PRIV_MULTIPLE);
    priv_addset(sp, PRIV_PROC_CLOCK_HIGHRES); /* Use high resolution timers */
    priv_addset(sp, PRIV_PROC_PRIOUP);        /* Raise process priority */
    priv_addset(sp, PRIV_PROC_PRIOCNTL);      /* Change process scheduling class */
    if (setppriv(PRIV_SET, PRIV_PERMITTED, sp)) {
      pa_log_error("Unable to set permitted privileges");
    }
    if (setppriv(PRIV_SET, PRIV_LIMIT, sp)) {
      pa_log_error("Unable to set privileges limits");
    }
    if (setppriv(PRIV_SET, PRIV_INHERITABLE, sp)) {
      pa_log_error("Unable to set inheritable privileges");
    }
    priv_freeset(sp);
#else
    pa_log_warn("Normally all extra capabilities would be dropped now, but "
                "that's impossible because PulseAudio was built without "
                "capabilities support.");
#endif
#endif
}
