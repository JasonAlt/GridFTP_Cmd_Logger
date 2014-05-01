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

void __cleanup(void) __attribute__((destructor)); 

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

	return _real_globus_xio_register_write(user_handle,
	                                       buffer,
	                                       buffer_length,
	                                       waitforbytes,
	                                       data_desc,
	                                       cb,
	                                       user_arg);
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
