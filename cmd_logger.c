/*
 * University of Illinois/NCSA Open Source License
 *
 * Copyright © 2012-2014 NCSA.  All rights reserved.
 *
 * Developed by:
 *
 * Storage Enabling Technologies (SET)
 *
 * Nation Center for Supercomputing Applications (NCSA)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the .Software.),
 * to deal with the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 *    + Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimers.
 *
 *    + Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimers in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    + Neither the names of SET, NCSA
 *      nor the names of its contributors may be used to endorse or promote
 *      products derived from this Software without specific prior written
 *      permission.
 *
 * THE SOFTWARE IS PROVIDED .AS IS., WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
  DEALINGS WITH THE SOFTWARE.
 */

/*
 * System includes.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <globus_gridftp_server.h>
#include <globus_i_gridftp_server_control.h>


#define ENV_LOGFILE_VAR  "CMD_LOGGER_LOGFILE"
#define ENV_LOGFILE_KEEP "CMD_LOGGER_KEEP_LOG"

void __cleanup(void) __attribute__((destructor)); 

typedef struct
{
    gss_cred_id_t                       cred;
    char *                              sbj;
    char *                              username;
    char *                              pw;
} gfs_l_file_session_t;

#ifdef EOF_DEBUG
typedef struct
{
    globus_mutex_t                      lock;
    globus_memory_t                     mem;
    globus_priority_q_t                 queue;
    globus_list_t *                     buffer_list;
    globus_gfs_operation_t              op;
    char *                              pathname;
    globus_xio_handle_t                 file_handle;
    globus_off_t                        file_offset;
    globus_off_t                        read_offset;
    globus_off_t                        read_length;
    int                                 pending_writes;
    int                                 pending_reads;
    globus_size_t                       block_size;
    int                                 optimal_count;
    int                                 node_ndx;
    globus_object_t *                   error;
    globus_bool_t                       first_read;
    globus_bool_t                       eof;
    globus_bool_t                       aborted;
    int                                 concurrency_check;
    int                                 concurrency_check_interval;
    char *                              expected_cksm;
    char *                              expected_cksm_alg;
    /* added for multicast stuff, but cold be genreally useful */
    gfs_l_file_session_t *              session;

    globus_result_t                     finish_result;
} globus_l_file_monitor_t;
#endif /* EOF_DEBUG */

static void (*_real_globus_l_gsc_read_cb)(globus_xio_handle_t            xio_handle,
                                          globus_result_t                result,
                                          globus_byte_t                * buffer,
                                          globus_size_t                  len,
                                          globus_size_t                  nbytes,
                                          globus_xio_data_descriptor_t   data_desc,
                                          void                         * user_arg) = NULL;

static globus_xio_handle_t _real_xio_handle = NULL;
static int    _cmd_logger_initialized = 0;
static FILE * _logfile_fp = NULL;
static char   _path_to_logfile[MAXPATHLEN];
#ifdef EOF_DEBUG
static globus_l_file_monitor_t * file_monitor = NULL;
#endif /* EOF_DEBUG */

void __cleanup()
{
	if (getenv(ENV_LOGFILE_KEEP))
		return;

	if (_cmd_logger_initialized && _path_to_logfile[0] != '\0')
		unlink(_path_to_logfile);
}

static void
_init_cmd_logger()
{
	char * logfile = NULL;

	if (_cmd_logger_initialized)
		return;

	_path_to_logfile[0] = '\0';

	logfile = getenv(ENV_LOGFILE_VAR);
	if (logfile == NULL)
		return;

	if ((strlen(logfile) + strlen(".123456") + 1) > sizeof(_path_to_logfile))
		return;

	snprintf(_path_to_logfile, sizeof(_path_to_logfile), "%s.%d", logfile, getpid());

	_logfile_fp = fopen(_path_to_logfile, "w");
	if (! _logfile_fp)
		return;

	_cmd_logger_initialized = 1;
}


static void
_incoming_command_hook(globus_byte_t   * buffer,
                       globus_size_t     len,
                       globus_size_t     nbytes,
                       globus_result_t   result)
{
	/*
	 * Save the incoming command.
	 */
	if (_logfile_fp)
	{
		fprintf(_logfile_fp, 
		        "CMD (b:%ld l:%d n:%d r:%d)\n%s\n", 
		        buffer,
		        len,
		        nbytes,
		        result,
		        buffer);
		fflush(_logfile_fp);
	}
}

static void
_outgoing_reply_hook(globus_byte_t * buffer,
                     globus_size_t   buffer_length)
{
	/*
	 * Save the outgoing reply.
	 */
	if (_logfile_fp)
	{
		fprintf(_logfile_fp, 
		        "REPLY (b:%ld l:%d)\n%s\n", 
		        buffer,
		        buffer_length,
		        buffer);
		fflush(_logfile_fp);
	}
}

static void
_fake_globus_l_gsc_read_cb(globus_xio_handle_t            xio_handle,
                           globus_result_t                result,
                           globus_byte_t                * buffer,
                           globus_size_t                  len,
                           globus_size_t                  nbytes,
                           globus_xio_data_descriptor_t   data_desc,
                           void                         * user_arg)
{

	/* Send the command to the hook. */
	_incoming_command_hook(buffer, len, nbytes, result);

	/* Call the real function. */
	_real_globus_l_gsc_read_cb(xio_handle, result, buffer, len, nbytes, data_desc, user_arg);
}

struct read_callback_args {
	globus_gridftp_server_read_cb_t   callback;
	void                            * arg;
};

#ifdef EOF_DEBUG
static void
_register_read_callback(globus_gfs_operation_t  op,
                        globus_result_t         result,
                        globus_byte_t *         buffer,
                        globus_size_t           nbytes,
                        globus_off_t            offset,
                        globus_bool_t           eof,
                        void                  * user_arg)
{
	struct read_callback_args * args = user_arg;

	if (_logfile_fp)
	{
		globus_mutex_lock(&file_monitor->lock);
		{
			fprintf(_logfile_fp, "GridFTP read Callback\n");
			fprintf(_logfile_fp, "\tPending writes: %d\n", file_monitor->pending_writes);
			fprintf(_logfile_fp, "\tPending reads: %d\n", file_monitor->pending_reads-1);
			fprintf(_logfile_fp, "\tEof: %s\n", (eof) ? "Yes": "No");
			fprintf(_logfile_fp, "\tError: %s\n", (result || file_monitor->finish_result) ? "Yes": "No");
			fflush(_logfile_fp);
		}
		globus_mutex_unlock(&file_monitor->lock);
	}

	args->callback(op, result, buffer, nbytes, offset, eof, args->arg);
	free(user_arg);
}


globus_result_t
globus_gridftp_server_register_read(
    globus_gfs_operation_t              op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,
    void *                              user_arg)
{
	void * module = NULL;
	static globus_result_t (*_real_globus_gridftp_server_register_read)(
	                              globus_gfs_operation_t              op,
                                  globus_byte_t *                     buffer,
                                  globus_size_t                       length,
                                  globus_gridftp_server_read_cb_t     callback,
                                  void *                              user_arg) = NULL;

	_init_cmd_logger();

	if (_real_globus_gridftp_server_register_read == NULL)
	{
		module = dlopen("libglobus_gridftp_server.so.6", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_globus_gridftp_server_register_read = dlsym(module, "globus_gridftp_server_register_read");
		if (dlerror())
			exit(1);
	}

	if (!file_monitor)
		file_monitor = user_arg;

	if (_logfile_fp)
	{
		fprintf(_logfile_fp, "Registering GridFTP read\n");
		fprintf(_logfile_fp, "\tPending writes: %d\n", file_monitor->pending_writes);
		fprintf(_logfile_fp, "\tPending reads: %d\n", file_monitor->pending_reads+1);
		fprintf(_logfile_fp, "\tEof: %s\n", (file_monitor->eof) ? "Yes": "No");
		fprintf(_logfile_fp, "\tError: %s\n", (file_monitor->finish_result) ? "Yes": "No");
		fflush(_logfile_fp);
	}

	struct read_callback_args * args = malloc(sizeof(struct read_callback_args));
	args->callback = callback;
	args->arg      = user_arg;

	return _real_globus_gridftp_server_register_read(op, buffer, length, _register_read_callback, args);
}

struct close_callback_args {
    globus_xio_callback_t   cb;
    void                  * user_arg;
};

static void
_xio_register_close_cb(globus_xio_handle_t   handle,
                       globus_result_t       result,
                       void                * user_arg)
{
	struct close_callback_args * args = user_arg;

	if (_logfile_fp)
	{
		if (result)
			fprintf(_logfile_fp, "Error in close callback\n");
		else
			fprintf(_logfile_fp, "Close callback completed\n");
		fflush(_logfile_fp);
	}
	file_monitor = NULL;

	args->cb(handle, result, args->user_arg);
	free(user_arg);
}

globus_result_t
globus_xio_register_close(
    globus_xio_handle_t                 handle,
    globus_xio_attr_t                   attr,
    globus_xio_callback_t               cb,
    void *                              user_arg)
{
	void * module = NULL;
	static globus_result_t (*_real_globus_xio_register_close)(globus_xio_handle_t     handle,
	                                                          globus_xio_attr_t       attr,
	                                                          globus_xio_callback_t   cb,
	                                                          void                  * user_arg);

	_init_cmd_logger();

	if (_real_globus_xio_register_close == NULL)
	{
		module = dlopen("libglobus_xio.so.0", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_globus_xio_register_close = dlsym(module, "globus_xio_register_close");
		if (dlerror())
			exit(1);
	}

	/* Ignore non-file closing calls. */
	if (!file_monitor || file_monitor->file_handle != handle)
		return _real_globus_xio_register_close(handle, attr, cb, user_arg);

	if (_logfile_fp)
	{
		fprintf(_logfile_fp, "Registering close \n");
		fflush(_logfile_fp);
	}

	struct close_callback_args * args = malloc(sizeof(struct close_callback_args));
	args->cb = cb;
	args->user_arg = user_arg;
	return _real_globus_xio_register_close(handle, attr, _xio_register_close_cb, args);
}
#endif /* EOF_DEBUG */

/*
 * Catch this function so that we can get the value of the xio handle.
 */
globus_result_t
globus_gridftp_server_control_start(globus_gridftp_server_control_t     server,
                                    globus_gridftp_server_control_attr_t attr,
                                    globus_xio_system_socket_t          system_handle,
                                    globus_gridftp_server_control_cb_t  done_cb,
                                    void *                              user_arg)
{
	void          * module = NULL;
	globus_result_t result = GLOBUS_SUCCESS;

	static globus_result_t (*_real_globus_gridftp_server_control_start) (
	                                globus_gridftp_server_control_t     server,
                                    globus_gridftp_server_control_attr_t attr,
                                    globus_xio_system_socket_t          system_handle,
                                    globus_gridftp_server_control_cb_t  done_cb,
                                    void *                              user_arg) = NULL;

	_init_cmd_logger();

	if (_real_globus_gridftp_server_control_start == NULL)
	{
		module = dlopen("libglobus_gridftp_server_control.so.0", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_globus_gridftp_server_control_start = dlsym(module, "globus_gridftp_server_control_start");
		if (dlerror())
			exit(1);
	}

	/* Call the real function. */
	result = _real_globus_gridftp_server_control_start(server, attr, system_handle, done_cb, user_arg);

	if (result == GLOBUS_SUCCESS)
		_real_xio_handle = server->xio_handle;

	return result;
}

/*
 * Catch this function and see if it is reading the control channel.
 */
globus_result_t
globus_xio_register_read(globus_xio_handle_t            handle,
                         globus_byte_t                * buffer,
                         globus_size_t                  buffer_length,
                         globus_size_t                  waitforbytes,
                         globus_xio_data_descriptor_t   data_desc,
                         globus_xio_data_callback_t     cb,
                         void *                         user_arg)
{
	void          * module = NULL;
	globus_result_t result = GLOBUS_SUCCESS;

	static globus_result_t (*_real_globus_xio_register_read)
	                             (globus_xio_handle_t            handle,
	                              globus_byte_t                * buffer,
	                              globus_size_t                  buffer_length,
	                              globus_size_t                  waitforbytes,
	                              globus_xio_data_descriptor_t   data_desc,
	                              globus_xio_data_callback_t     cb,
	                              void *                         user_arg) = NULL;

	if (_real_globus_xio_register_read == NULL)
	{
		module = dlopen("libglobus_xio.so.0", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_globus_xio_register_read = dlsym(module, "globus_xio_register_read");
		if (dlerror())
			exit(1);
	}

	if (handle != _real_xio_handle)
	{
		return _real_globus_xio_register_read(handle,
		                                      buffer,
		                                      buffer_length,
		                                      waitforbytes,
		                                      data_desc,
		                                      cb,
		                                      user_arg);
	}

	if (_real_globus_l_gsc_read_cb == NULL)
		_real_globus_l_gsc_read_cb = cb;

	return _real_globus_xio_register_read(handle, 
	                                      buffer, 
	                                      buffer_length, 
	                                      waitforbytes, 
	                                      data_desc, 
	                                      _fake_globus_l_gsc_read_cb,
	                                      user_arg);

}

#ifdef EOF_DEBUG
struct xio_register_write_cb {
    globus_xio_data_callback_t   cb;
	void                       * user_arg;
};

static void
_xio_register_write_cb(
    globus_xio_handle_t                 xio_handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
	struct xio_register_write_cb * args = user_arg;
	globus_l_file_monitor_t * file_monitor = args->user_arg;

	if (_logfile_fp)
	{
		globus_mutex_lock(&file_monitor->lock);
		{
			fprintf(_logfile_fp, "Buffer written to file\n");
			fprintf(_logfile_fp, "\tPending writes: %d\n", file_monitor->pending_writes-1);
			fprintf(_logfile_fp, "\tPending reads: %d\n", file_monitor->pending_reads);
			fprintf(_logfile_fp, "\tEof: %s\n", (file_monitor->eof) ? "Yes": "No");
			fprintf(_logfile_fp, "\tError: %s\n", (result || file_monitor->finish_result) ? "Yes": "No");
			fflush(_logfile_fp);
		}
		globus_mutex_unlock(&file_monitor->lock);
	}

	return args->cb(xio_handle, result, buffer, len, nbytes, data_desc, args->user_arg);
	free(args);
}
#endif /* EOF_DEBUG */

globus_result_t
globus_xio_register_write(
    globus_xio_handle_t                 user_handle,
    globus_byte_t *                     buffer,
    globus_size_t                       buffer_length,
    globus_size_t                       waitforbytes,
    globus_xio_data_descriptor_t        data_desc,
    globus_xio_data_callback_t          cb,
    void *                              user_arg)
{
	void          * module = NULL;
	globus_result_t result = GLOBUS_SUCCESS;

	static globus_result_t
	        (*_real_globus_xio_register_write)(globus_xio_handle_t            handle,
	                                           globus_byte_t                * buffer,
	                                           globus_size_t                  buffer_length,
	                                           globus_size_t                  waitforbytes,
	                                           globus_xio_data_descriptor_t   data_desc,
	                                           globus_xio_data_callback_t     cb,
	                                           void *                         user_arg) = NULL;

	if (_real_globus_xio_register_write == NULL)
	{
		module = dlopen("libglobus_xio.so.0", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_globus_xio_register_write = dlsym(module, "globus_xio_register_write");
		if (dlerror())
			exit(1);
	}

	if (user_handle == _real_xio_handle)
		_outgoing_reply_hook(buffer, buffer_length);

#ifdef EOF_DEBUG
	if (!file_monitor || file_monitor->file_handle != user_handle)
#endif /* EOF_DEBUG */
		return _real_globus_xio_register_write(user_handle,
		                                       buffer,
		                                       buffer_length,
		                                       waitforbytes,
		                                       data_desc,
		                                       cb,
		                                       user_arg);

#ifdef EOF_DEBUG
	struct xio_register_write_cb * args = malloc(sizeof(struct xio_register_write_cb));
	args->cb = cb;
	args->user_arg = user_arg;
	return _real_globus_xio_register_write(user_handle,
	                                       buffer,
	                                       buffer_length,
	                                       waitforbytes,
	                                       data_desc,
	                                       _xio_register_write_cb,
	                                       args);
#endif /* EOF_DEBUG */
}

int
setuid(uid_t Uid)
{
	void * module = NULL;
	int    retval = 0;

	static int (*_real_setuid) (uid_t Uid) = NULL;

	if (_real_setuid == NULL)
	{
		module = dlopen("libc.so.6", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_setuid = dlsym(module, "setuid");
		if (dlerror())
			exit(1);
	}

	/*
	 * Change the owner of our log file, this will allow us to delete it later if
	 * the directory is sticky.
	 */
	if (_logfile_fp)
		fchown(fileno(_logfile_fp), Uid, -1);

	return _real_setuid(Uid);
}

int
setgid(gid_t Gid)
{
	void * module = NULL;
	int    retval = 0;

	static int (*_real_setgid) (gid_t Gid) = NULL;

	if (_real_setgid == NULL)
	{
		module = dlopen("libc.so.6", RTLD_LAZY|RTLD_LOCAL);

		if (!module)
			exit(1);

		/* Clear any previous error. */
		dlerror();

		_real_setgid = dlsym(module, "setgid");
		if (dlerror())
			exit(1);
	}

	/*
	 * Change the owner of our log file, this will allow us to delete it later if
	 * the directory is sticky.
	 */
	if (_logfile_fp)
		fchown(fileno(_logfile_fp), -1, Gid);

	return _real_setgid(Gid);
}
