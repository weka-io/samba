/* ========================================================================== **
 * vfs_wekafs.c
 *
 * SMB3 recoverable handle support.
 *
 * Copyright (C) Christopher R. Hertel, 2017
 * $Id: vfs_wekafs.c; 2017-06-15 11:01:53 -0500; Christopher R. Hertel$
 *
 * ========================================================================== **
 * License:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * ========================================================================== **
 * Notes:
 *  This is currently a placeholder and/or skeleton upon which the WekaFS
 *  VFS module will be built.  It logs particular function calls going
 *  through the VFS layer, but does not impede processing of those calls.
 *
 * ========================================================================== **
 */

/* Samba includes. */
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"


/* -------------------------------------------------------------------------- **
 *  DBGC_CLASS          - The debug class under which messages are logged
 *                        from within this module.
 */

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS


/* -------------------------------------------------------------------------- **
 * Global Constants
 */

const char *const wekafs_mod_name = "wekafs";


/* -------------------------------------------------------------------------- **
 * Functions
 */

/** Handle a Tree Connect request.
 *  @param [in,out] handle  - Pointer to the VFS handle structure.
 *  @param [in]     service - The share name (not the path).
 *  @param [in]     user    - The username, which is passed down the
 *                            stack.
 *  @returns  This function returns zero (0) on success, and a
 *            negative value on failure.
 *
 *  \b Notes:
 *  - ???
 *
 */
static int vfs_wekafs_connect( vfs_handle_struct *handle,
                               const char        *service,
                               const char        *user )
  {
  int result;

  /* Call down the stack first.
   * If the call fails, just return whatever the lower level returned.
   */
  errno = 0;
  if( (result = SMB_VFS_NEXT_CONNECT( handle, service, user )) < 0 )
    return( result );

  /* Now the real work begins.
   *  Check LP variable status here.
   */

  /* Finished.  */
  DEBUG( 0, ( "crh> TreeConn: [User: %s, Service: %s]\n", user, service ) );
  return( 0 );
  } /* vfs_wekafs_connect */

/* File operations */

/** Posix-level File Open.
 */
static int vfs_wekafs_open( vfs_handle_struct   *handle,
                            struct smb_filename *smb_fname,
                            files_struct        *fsp,
                            int                  flags,
                            mode_t               mode )
  {
  /* Call down the VFS stack to open/create the file. */
  errno = 0;
  fsp->fh->fd = SMB_VFS_NEXT_OPEN( handle, smb_fname, fsp, flags, mode );
  if( fsp->fh->fd < 0 )
    return( fsp->fh->fd );

  DEBUG( 0, ( "crh> Opened file %s.\n", fsp_str_dbg( fsp ) ) );
  return( 0 );
  } /* vfs_wekafs_open */

/**
 */
static int vfs_wekafs_close( vfs_handle_struct *handle,
                             files_struct      *fsp )
  {
  int result;

  /* Call down the VFS stack. */
  errno = 0;
  result = SMB_VFS_NEXT_CLOSE( handle, fsp );
  if( result < 0 )
    return( result );

  DEBUG( 0, ( "crh> Closing file %s.\n", fsp_str_dbg( fsp ) ) );
  return( 0 );
  } /* vfs_wekafs_close */

/**
 */
static NTSTATUS vfs_wekafs_durable_cookie( struct vfs_handle_struct *handle,
                                           struct files_struct      *fsp,
                                           TALLOC_CTX               *mem_ctx,
                                           DATA_BLOB                *cookie )
  {
  NTSTATUS status;

  errno = 0;
  status = SMB_VFS_NEXT_DURABLE_COOKIE( handle, fsp, mem_ctx, cookie );
  if( !NT_STATUS_IS_OK( status ) )
    return( status );

  DEBUG( 0, ( "crh> Durable_Cookie: [File: %s, FIX: Dump Cookie.]\n",
              fsp_str_dbg( fsp ) ) );
  return( NT_STATUS_OK );
  } /* vfs_wekafs_durable_cookie */

/**
 */
static NTSTATUS vfs_wekafs_durable_disconnect(
                                          struct vfs_handle_struct *handle,
                                          struct files_struct      *fsp,
                                          const DATA_BLOB           old_cookie,
                                          TALLOC_CTX               *mem_ctx,
                                          DATA_BLOB                *new_cookie )
  {
  NTSTATUS status;

  errno = 0;
  status = SMB_VFS_NEXT_DURABLE_DISCONNECT( handle,
                                            fsp,
                                            old_cookie,
                                            mem_ctx,
                                            new_cookie );
  if( !NT_STATUS_IS_OK( status ) )
    return( status );

  DEBUG( 0, ( "crh> Durable_Disconnect: [File: %s\n]", fsp_str_dbg( fsp ) ) );
  return( NT_STATUS_OK );
  } /* vfs_wekafs_durable_disconnect */

/**
 */
static NTSTATUS vfs_wekafs_durable_reconnect(
                                        struct vfs_handle_struct *handle,
                                        struct smb_request       *smb1req,
                                        struct smbXsrv_open      *op,
                                        const DATA_BLOB           old_cookie,
                                        TALLOC_CTX               *mem_ctx,
                                        struct files_struct     **fsp,
                                        DATA_BLOB                *new_cookie )
  {
  NTSTATUS status;

  errno = 0;
  status = SMB_VFS_NEXT_DURABLE_RECONNECT( handle,
                                           smb1req,
                                           op,
                                           old_cookie,
                                           mem_ctx,
                                           fsp,
                                           new_cookie );
  if( !NT_STATUS_IS_OK( status ) )
    return( status );

  DEBUG( 0, ( "crh> Durable_Reconnect: [File: %s, FIX: Dump it!]\n",
              fsp_str_dbg( *fsp ) ) );
  return( NT_STATUS_OK );
  } /* vfs_wekafs_durable_reconnect */


/* -------------------------------------------------------------------------- **
 * Module Initialization
 */

static struct vfs_fn_pointers vfs_wekafs_fns =
  {
  /* Disk operations */
  .connect_fn = vfs_wekafs_connect,

  /* File operations */
  .open_fn  = vfs_wekafs_open,
  .close_fn = vfs_wekafs_close,

  /* durable handle operations */
  .durable_cookie_fn     = vfs_wekafs_durable_cookie,
  .durable_disconnect_fn = vfs_wekafs_durable_disconnect,
  .durable_reconnect_fn  = vfs_wekafs_durable_reconnect
  };

/**
 */
NTSTATUS vfs_wekafs_init( void );
NTSTATUS vfs_wekafs_init( void )
  {
  /* Enable features here.
   */

  /* Register the module. */
  return smb_register_vfs( SMB_VFS_INTERFACE_VERSION,
                           wekafs_mod_name,
                           &vfs_wekafs_fns );
  } /* vfs_wekafs_init */

/* ========================================================================== */



/* ofer was here */

