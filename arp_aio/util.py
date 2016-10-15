import grp
import os
import pwd


def drop_privileges(uid_name=None, gid_name=None, umask=None):
    if os.getuid() != 0:
        # Not running as root
        return

    if uid_name is None:
        sudo_uid = os.getenv('SUDO_UID')
        sudo_gid = os.getenv('SUDO_GID')
        if sudo_uid and sudo_gid:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
        else:
            uid = pwd.getpwnam('nobody').pw_uid
            gid = grp.getgrnam('nogroup').gr_gid
    else:
        uid = pwd.getpwnam(uid_name).pw_uid
        gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])
    # Set new UID and GID
    os.setgid(gid)
    os.setuid(uid)
    if umask:
        os.umask(umask)
