/*
 * Copyright (c) 2020, Felix Dörre
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/zfs_context.h>
#include <sys/fs/zfs.h>
#include <sys/dsl_crypt.h>
#include <sys/byteorder.h>
#include <libzfs.h>

#include <syslog.h>

#include <sys/zio_crypt.h>
#include <openssl/evp.h>

#define	PAM_SM_AUTH
#define	PAM_SM_PASSWORD
#define	PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <signal.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <pwd.h>

#include <sys/mman.h>

static const char *PASSWORD_VAR_NAME = "pam_zfs_key_authtok";

static libzfs_handle_t *libzfs;

static void destroy_pw(pam_handle_t *pamh, void *data, int errcode);

typedef struct {
	size_t len;
	char *value;
} password;

static password *
alloc_pw_size(size_t len)
{
	password *pw = malloc(sizeof (password));
	pw->len = len;
	pw->value = malloc(len);
	mlock(pw->value, pw->len);
	return (pw);
}

static password *
alloc_pw_string(const char *source)
{
	password *pw = malloc(sizeof (password));
	pw->len = strlen(source) + 1;
	pw->value = malloc(pw->len);
	mlock(pw->value, pw->len);
	memcpy(pw->value, source, pw->len);
	return (pw);
}

static void
pw_free(password *pw)
{
	bzero(pw->value, pw->len);
	munlock(pw->value, pw->len);
	free(pw->value);
	free(pw);
}

static password *
pw_fetch(pam_handle_t *pamh)
{
	const char *token;
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "couldn't get password from PAM stack");
		return (NULL);
	}
	return (alloc_pw_string(token));
}

static const password *
pw_fetch_lazy(pam_handle_t *pamh)
{
	password *pw = pw_fetch(pamh);
	if (pw == NULL) {
		return (NULL);
	}
	int ret = pam_set_data(pamh, PASSWORD_VAR_NAME, pw, destroy_pw);
	if (ret != PAM_SUCCESS) {
		pw_free(pw);
		pam_syslog(pamh, LOG_ERR, "pam_set_data failed");
		return (NULL);
	}
	return (pw);
}

static const password *
pw_get(pam_handle_t *pamh)
{
	const password *authtok = NULL;
	int ret = pam_get_data(pamh, PASSWORD_VAR_NAME,
	    (const void**)(&authtok));
	if (ret == PAM_SUCCESS)
		return (authtok);
	if (ret == PAM_NO_MODULE_DATA)
		return (pw_fetch_lazy(pamh));
	pam_syslog(pamh, LOG_ERR, "password not available");
	return (NULL);
}

static int
pw_clear(pam_handle_t *pamh)
{
	int ret = pam_set_data(pamh, PASSWORD_VAR_NAME, NULL, NULL);
	if (ret != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "clearing password failed");
		return (-1);
	}
	return (0);
}

static void
destroy_pw(pam_handle_t *pamh, void *data, int errcode)
{
	if (data != NULL) {
		pw_free((password*) data);
	}
}

static void
pam_zfs_init(void)
{
	libzfs = libzfs_init();
	libzfs_core_init();
}

static void
pam_zfs_free(void)
{
	libzfs_core_fini();
	libzfs_fini(libzfs);
}

static password *
prepare_passphrase(pam_handle_t *pamh, zfs_handle_t *ds,
    const char *passphrase, nvlist_t *nvlist)
{
	password *key = alloc_pw_size(WRAPPING_KEY_LEN);
	if (!key) {
		return (NULL);
	}
	uint64_t salt;
	uint64_t iters;
	if (nvlist != NULL) {
		int fd = open("/dev/urandom", O_RDONLY);
		int bytes_read = 0;
		char *buf = (char *)&salt;
		size_t bytes = sizeof (uint64_t);
		while (bytes_read < bytes) {
			ssize_t len = read(fd, buf + bytes_read, bytes
			    - bytes_read);
			if (len < 0) {
				close(fd);
				pw_free(key);
				return (NULL);
			}
			bytes_read += len;
		}
		close(fd);

		if (nvlist_add_uint64(nvlist,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), salt)) {
			pam_syslog(pamh, LOG_ERR,
			    "failed to add salt to nvlist");
			pw_free(key);
			return (NULL);
		}
		iters = DEFAULT_PBKDF2_ITERATIONS;
		if (nvlist_add_uint64(nvlist, zfs_prop_to_name(
		    ZFS_PROP_PBKDF2_ITERS), iters)) {
			pam_syslog(pamh, LOG_ERR,
			    "failed to add iters to nvlist");
			pw_free(key);
			return (NULL);
		}
	} else {
		salt = zfs_prop_get_int(ds, ZFS_PROP_PBKDF2_SALT);
		iters = zfs_prop_get_int(ds, ZFS_PROP_PBKDF2_ITERS);
	}

	salt = LE_64(salt);
	if (!PKCS5_PBKDF2_HMAC_SHA1((char *)passphrase,
	    strlen(passphrase), ((uint8_t *)&salt),
	    sizeof (uint64_t), iters, WRAPPING_KEY_LEN,
	    (uint8_t *)key->value)) {
		pam_syslog(pamh, LOG_ERR, "pbkdf failed");
		pw_free(key);
		return (NULL);
	}
	return (key);
}

static int
is_key_loaded(pam_handle_t *pamh, const char *ds_name)
{
	zfs_handle_t *ds = zfs_open(libzfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}
	int keystatus = zfs_prop_get_int(ds, ZFS_PROP_KEYSTATUS);
	zfs_close(ds);
	return (keystatus != ZFS_KEYSTATUS_UNAVAILABLE);
}

static int
change_key(pam_handle_t *pamh, const char *ds_name,
    const char *passphrase)
{
	zfs_handle_t *ds = zfs_open(libzfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}
	nvlist_t *nvlist = fnvlist_alloc();
	password *key = prepare_passphrase(pamh, ds, passphrase, nvlist);
	if (key == NULL) {
		nvlist_free(nvlist);
		zfs_close(ds);
		return (-1);
	}
	if (nvlist_add_string(nvlist,
	    zfs_prop_to_name(ZFS_PROP_KEYLOCATION),
	    "prompt")) {
		pam_syslog(pamh, LOG_ERR, "nvlist_add failed for keylocation");
		pw_free(key);
		nvlist_free(nvlist);
		zfs_close(ds);
		return (-1);
	}
	if (nvlist_add_uint64(nvlist,
	    zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    ZFS_KEYFORMAT_PASSPHRASE)) {
		pam_syslog(pamh, LOG_ERR, "nvlist_add failed for keyformat");
		pw_free(key);
		nvlist_free(nvlist);
		zfs_close(ds);
		return (-1);
	}
	int ret = lzc_change_key(ds_name, DCP_CMD_NEW_KEY, nvlist,
	    (uint8_t *)key->value, WRAPPING_KEY_LEN);
	pw_free(key);
	if (ret) {
		pam_syslog(pamh, LOG_ERR, "change_key failed: %d", ret);
		nvlist_free(nvlist);
		zfs_close(ds);
		return (-1);
	}
	return (0);
}

static int
decrypt_mount(pam_handle_t *pamh, const char *ds_name,
    const char *passphrase)
{
	zfs_handle_t *ds = zfs_open(libzfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}
	password *key = prepare_passphrase(pamh, ds, passphrase, NULL);
	if (key == NULL) {
		zfs_close(ds);
		return (-1);
	}
	int ret = lzc_load_key(ds_name, B_FALSE, (uint8_t *)key->value,
	    WRAPPING_KEY_LEN);
	pw_free(key);
	if (ret) {
		pam_syslog(pamh, LOG_ERR, "load_key failed: %d", ret);
		zfs_close(ds);
		return (-1);
	}
	ret = zfs_mount(ds, NULL, 0);
	if (ret) {
		pam_syslog(pamh, LOG_ERR, "mount failed: %d", ret);
		zfs_close(ds);
		return (-1);
	}
	return (0);
}

static int
unmount_unload(pam_handle_t *pamh, const char *ds_name)
{
	zfs_handle_t *ds = zfs_open(libzfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}
	int ret = zfs_unmount(ds, NULL, 0);
	if (ret) {
		pam_syslog(pamh, LOG_ERR, "zfs_unmount failed with: %d", ret);
		zfs_close(ds);
		return (-1);
	}

	ret = lzc_unload_key(ds_name);
	if (ret) {
		pam_syslog(pamh, LOG_ERR, "unload_key failed with: %d", ret);
		zfs_close(ds);
		return (-1);
	}
	zfs_close(ds);
	return (0);
}

static void
sigchild_default(struct sigaction *oldact)
{
	struct sigaction newact;
	newact.sa_handler = SIG_DFL;
	newact.sa_flags = 0;
	sigfillset(&newact.sa_mask);
	sigaction(SIGCHLD, &newact, oldact);
}

static void
sigchild_default_reset(struct sigaction *oldact)
{
	sigaction(SIGCHLD, oldact, NULL);
}

typedef struct {
	char *homes_prefix;
	uid_t uid;
	const char *username;
} zfs_key_config;

static int
zfs_key_config_load(pam_handle_t *pamh, zfs_key_config *config,
    int argc, const char **argv)
{
	config->homes_prefix = strdup("rpool/home");
	const char *name;
	if (pam_get_user(pamh, &name, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "couldn't get username from PAM stack");
		free(config->homes_prefix);
		return (-1);
	}
	struct passwd *entry = getpwnam(name);
	config->uid = entry->pw_uid;
	config->username = name;
	for (int c = 0; c < argc; c++) {
		if (strncmp(argv[c], "homes=", 6) == 0) {
			free(config->homes_prefix);
			config->homes_prefix = strdup(argv[c] + 6);
		}
	}
	return (0);
}

static void
zfs_key_config_free(zfs_key_config *config)
{
	free(config->homes_prefix);
}

static char *
zfs_key_config_get_dataset(zfs_key_config *config)
{
	size_t len = ZFS_MAX_DATASET_NAME_LEN;
	char *ret = malloc(len + 1);
	ret[0] = 0;
	strncat(ret, config->homes_prefix, len);
	strncat(ret, "/", len);
	strncat(ret, config->username, len);
	return (ret);
}

static int
zfs_key_config_modify_session_counter(pam_handle_t *pamh,
    zfs_key_config *config, int delta)
{
	const char *runtime_path = RUNSTATEDIR "/pam_zfs_key";
	if (mkdir(runtime_path, S_IRWXU) != 0 && errno != EEXIST) {
		pam_syslog(pamh, LOG_ERR, "Can't create runtime path: %d",
		    errno);
		return (-1);
	}
	if (chown(runtime_path, 0, 0) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't chown runtime path: %d",
		    errno);
		return (-1);
	}
	if (chmod(runtime_path, S_IRWXU) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't chmod runtime path: %d",
		    errno);
		return (-1);
	}
	char counter_path[strlen(runtime_path) + 1 + 10 + 1];
	snprintf(counter_path, sizeof (counter_path), RUNSTATEDIR
	    "/pam_zfs_key/%d", config->uid);
	const int fd = open(counter_path,
	    O_RDWR | O_CLOEXEC | O_CREAT | O_NOFOLLOW,
	    S_IRUSR | S_IWUSR);
	if (fd < 0) {
		pam_syslog(pamh, LOG_ERR, "Can't open counter file: %d", errno);
		return (-1);
	}
	if (flock(fd, LOCK_EX) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't lock counter file: %d", errno);
		close(fd);
		return (-1);
	}
	char counter[20];
	char *pos = counter;
	int remaining = sizeof (counter) - 1;
	int ret;
	counter[sizeof (counter) - 1] = 0;
	while (remaining > 0 && (ret = read(fd, pos, remaining)) > 0) {
		remaining -= ret;
		pos += ret;
	}
	*pos = 0;
	long int counterValue = strtol(counter, NULL, 10);
	counterValue += delta;
	if (counterValue < 0) {
		counterValue = 0;
	}
	lseek(fd, 0, SEEK_SET);
	if (ftruncate(fd, 0) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't truncate counter file: %d",
		    errno);
		close(fd);
		return (-1);
	}
	snprintf(counter, sizeof (counter), "%ld", counterValue);
	remaining = strlen(counter);
	pos = counter;
	while (remaining > 0 && (ret = write(fd, pos, remaining)) > 0) {
		remaining -= ret;
		pos += ret;
	}
	close(fd);
	return (counterValue);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	if (pw_fetch_lazy(pamh) == NULL) {
		return (PAM_AUTH_ERR);
	}

	return (PAM_SUCCESS);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return (PAM_SUCCESS);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_PERM_DENIED);
	}
	zfs_key_config config;
	if (zfs_key_config_load(pamh, &config, argc, argv) == -1) {
		return (PAM_SERVICE_ERR);
	}
	if (config.uid < 1000) {
		return (PAM_SUCCESS);
	}
	{
		pam_zfs_init();
		char *dataset = zfs_key_config_get_dataset(&config);
		int key_loaded = is_key_loaded(pamh, dataset);
		if (key_loaded == -1) {
			free(dataset);
			pam_zfs_free();
			return (PAM_SERVICE_ERR);
		}
		free(dataset);
		pam_zfs_free();
		if (! key_loaded) {
			pam_syslog(pamh, LOG_ERR,
			    "key not loaded, returning try_again");
			return (PAM_PERM_DENIED);
		}
	}

	if ((flags & PAM_UPDATE_AUTHTOK) != 0) {
		const password *token = pw_get(pamh);
		if (token == NULL) {
			zfs_key_config_free(&config);
			return (PAM_SERVICE_ERR);
		}
		struct sigaction oldact;
		sigchild_default(&oldact);
		pid_t pid = fork();
		if (pid == 0) {
			if (setuid(0)) {
				perror("setuid");
			}
			pam_zfs_init();
			char *dataset = zfs_key_config_get_dataset(&config);
			if (change_key(pamh, dataset, token->value) == -1) {
				free(dataset);
				pam_zfs_free();
				exit(1);
			}
			free(dataset);
			pam_zfs_free();
			exit(42);
		}
		if (pw_clear(pamh) == -1) {
			sigchild_default_reset(&oldact);
			zfs_key_config_free(&config);
			return (PAM_SERVICE_ERR);
		}
		int wstatus;
		if (waitpid(pid, &wstatus, 0) != pid) {
			perror("wait");
			sigchild_default_reset(&oldact);
			zfs_key_config_free(&config);
			return (PAM_SERVICE_ERR);
		}
		sigchild_default_reset(&oldact);
		zfs_key_config_free(&config);
		if (WEXITSTATUS(wstatus) != 42) {
			return (PAM_SERVICE_ERR);
		}
	}
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_SUCCESS);
	}
	zfs_key_config config;
	zfs_key_config_load(pamh, &config, argc, argv);
	if (config.uid < 1000) {
		return (PAM_SUCCESS);
	}

	int counter = zfs_key_config_modify_session_counter(pamh, &config, 1);
	if (counter != 1) {
		zfs_key_config_free(&config);
		return (PAM_SUCCESS);
	}

	struct sigaction oldact;
	sigchild_default(&oldact);
	const password *token = pw_get(pamh);
	if (token == NULL) {
		sigchild_default_reset(&oldact);
		zfs_key_config_free(&config);
		return (PAM_SESSION_ERR);
	}
	pid_t pid = fork();
	if (pid == 0) {
		if (setuid(0)) {
			perror("setuid");
		}
		pam_zfs_init();
		char *dataset = zfs_key_config_get_dataset(&config);
		if (decrypt_mount(pamh, dataset, token->value) == -1) {
			free(dataset);
			pam_zfs_free();
			exit(1);
		}
		free(dataset);
		pam_zfs_free();
		if (pw_clear(pamh) == -1) {
			exit(1);
		}
		exit(0);
	}
	if (pw_clear(pamh) == -1) {
		sigchild_default_reset(&oldact);
		zfs_key_config_free(&config);
		return (PAM_SESSION_ERR);
	}
	int wstatus;
	if (waitpid(pid, &wstatus, 0) != pid) {
		perror("wait");
		sigchild_default_reset(&oldact);
		zfs_key_config_free(&config);
		return (PAM_SESSION_ERR);
	}
	sigchild_default_reset(&oldact);
	zfs_key_config_free(&config);
	if (WEXITSTATUS(wstatus) != 0) {
		return (PAM_SESSION_ERR);
	}
	return (PAM_SUCCESS);

}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_SUCCESS);
	}
	zfs_key_config config;
	zfs_key_config_load(pamh, &config, argc, argv);
	if (config.uid < 1000) {
		return (PAM_SUCCESS);
	}

	int counter = zfs_key_config_modify_session_counter(pamh, &config, -1);
	if (counter != 0) {
		zfs_key_config_free(&config);
		return (PAM_SUCCESS);
	}

	struct sigaction oldact;
	sigchild_default(&oldact);
	pid_t pid = fork();
	if (pid == 0) {
		if (setuid(0)) {
			perror("setuid");
		}
		pam_zfs_init();
		char *dataset = zfs_key_config_get_dataset(&config);
		if (unmount_unload(pamh, dataset) == -1) {
			free(dataset);
			pam_zfs_free();
			exit(1);
		}
		free(dataset);
		pam_zfs_free();
		exit(0);
	}

	int wstatus;
	if (waitpid(pid, &wstatus, 0) != pid) {
		perror("wait");
		sigchild_default_reset(&oldact);
		zfs_key_config_free(&config);
		return (PAM_SESSION_ERR);
	}
	sigchild_default_reset(&oldact);
	zfs_key_config_free(&config);
	if (WEXITSTATUS(wstatus) != 0) {
		return (PAM_SESSION_ERR);
	}
	return (PAM_SUCCESS);
}
