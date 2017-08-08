/* ========================================================================== **
 * vfs_weka_xattr_db.c
 *
 * Store extended attributes in an external database.
 *
 * Copyright (C) Christopher R. Hertel, 2017
 * $Id: vfs_weka_xattr_db.c; 2017-07-14 16:24:13 -0500; Christopher R. Hertel$
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
 *
 *  This is KLUDGE CODE!  Not meant for general consumption!
 *    + Void where prohibited,
 *    + Your mileage will vary,
 *    + Right lane must exit,
 *    + You have been warned!
 *
 *  Okay, so...
 *
 *  Extended Attributes (EAs) provide a simple key:value store associated
 *  with individual files.  Samba uses EAs to store Windows metadata
 *  including Windows attribute bits and ACLs.  POSIX ACLs are also stored
 *  in EAs.
 *
 *  Unfortunately, WekaFS doesn't support EAs (yet), so the kludge-around
 *  is to use a networked database to store the EAs and do our level best
 *  to keep them in sync with the actual files.  This is, overall, a losing
 *  proposition.  It will, however, provide sufficient support for EAs to
 *  allow testing to continue.
 *
 *  Using a database for EA management has some obvious problems.  For
 *  example, the EAs are not available for viewing, update, or deletion
 *  except via the VFS.  Local processes, including NFS, are unaware of
 *  the EAs.  If a file is deleted by a local process, the EAs will still
 *  be lurking in the database.  That can get messy.
 *
 *  Another problem is that the database operations may not be atomic.
 *  The database in use by this module, for example, doesn't support
 *  transactions or record locks, so we can't be sure there won't be any
 *  conflicts...but that's only a highly critical semantic detail.
 *
 *  Another thingy:  The database in use was chosen because it's small, fast,
 *  and is designed to be accessed over a network connection.  Unfortunately,
 *  it turned out that this particular database (which is modeled on the much
 *  more powerful <memcached> system) does not support "binary" mode.  As a
 *  result, I had to use base64 encoding to create "valid" text-only names
 *  and values.  That's a mega-kludge.  Uhgly...but it works.
 *
 *  Oh, and the code is sloppy.  There are a lot of places where (if it were
 *  worth the time--which it isn't) redundant code could be reduced,
 *  comments could be improved, code safety could be improved, error handling
 *  could be added, etc., etc.
 *
 *  Test code only.
 *
 * ========================================================================== **
 */

/* Regular includes. */
#include <stdarg.h>

/* Networking includes. */
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

/* Samba includes. */
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"


/* -------------------------------------------------------------------------- **
 * Macros:
 *
 *  These three internal macros are based on their equivalents in
 *  ../source3/include/vfs.h.  They are used to set/get/free a datablob
 *  that is connected to a VFS file handle.  That blob is used to store
 *  relevant state information.
 *
 *  HANDLE_GET_DATA()   - Retrieve an arbitrary data blob stored with a VFS
 *                        file handle.
 *                          handle  - A VFS file handle pointer.
 *                          dataptr - The retrieved data pointer, which may
 *                                    be NULL.  The calling code should check
 *                                    the value of <dataptr>.
 *                          type    - The type of the data stored in the
 *                                    data blob.  The pointer to the data
 *                                    blob is cast to (type *) before it is
 *                                    assigned to <dataptr>.
 *
 *  HANDLE_SET_DATA()   - Set (or reset) the data blob associated with a VFS
 *                        file handle.
 *                          handle  - A VFS file handle pointer.
 *                          dataptr - The data to be stored.
 *                          free_fn - A pointer to a function that will be
 *                                    used to free the stored data when it
 *                                    is no longer needed.  This function
 *                                    takes a pointer to the data pointer as
 *                                    input (void **).
 *
 *  HANDLE_FREE_DATA()  - Free the data blob stored with a VFS file handle.
 *                          handle  - A VFS file handle pointer.  The handle
 *                                    must be non-NULL, and the <free_data>
 *                                    function must be defined.  If not, the
 *                                    data blob (if it exists) will not be
 *                                    freed.
 */

#define HANDLE_GET_DATA( handle, dataptr, type ) \
  { \
  dataptr = (type *)((handle) ? ((handle)->data) : NULL); \
  if( NULL == dataptr ) \
    DEBUG( 0, ("%s(): Failed to get vfs_handle->data\n", __FUNCTION__) ); \
  }

#define HANDLE_SET_DATA( handle, dataptr, free_fn ) \
  { \
  if( handle ) \
    { \
    if( (handle)->free_data ) \
      { \
      (handle)->free_data( &((handle)->data) ); \
      } \
    (handle)->data      = (void *)dataptr; \
    (handle)->free_data = free_fn; \
    } \
  else \
    { \
    DEBUG( 0, ("%s(): NULL handle setting vfs_handle->data\n", __FUNCTION__) );\
    } \
  }

#define HANDLE_FREE_DATA( handle ) \
  { \
  if( (handle) && (handle)->free_data ) \
    { \
    (handle)->free_data( &(handle)->data ); \
    } \
  }


/* -------------------------------------------------------------------------- **
 * Definitions and Redefinitions
 *
 *  BSIZE               - We use a small line buffer to read input from the
 *                        database server.  This is the size (in bytes) of
 *                        that input buffer.
 *
 *  ENC64LEN            - Given a length value, in bytes, this calculates the
 *                        number of bytes that will be required to encode an
 *                        object using the base64 encoding scheme.
 *
 *  DEC64LEN            - Given the length, in bytes, of a base64 input, this
 *                        macro returns the number of bytes required for the
 *                        decoded object.
 *
 *  DEF_PORT_STR        - The default database port number, presented as a
 *                        string.  We use a string because getaddrinfo(3)
 *                        expects a string and because we will try to read
 *                        the port number from the smb.conf file, and that
 *                        will give us a string.  We're just keeping things
 *                        consistent.
 *
 *  DBGC_CLASS          - The debug class under which messages are logged
 *                        from within this module.
 *
 *  ERROR_NOT_SUPPORTED - The POSIX error code to use when a request cannot
 *                        be completed.  ENOSYS is a fallback to ENOTSUP if
 *                        the latter has not been defined.
 */

#define BSIZE 128

#define ENC64LEN( S ) ((((S) * 8) + 5) / 6)
#define DEC64LEN( S ) (((S) * 6) / 8 )

#define DEF_PORT_STR "21201"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#if defined( ENOTSUP )
  #define ERROR_NOT_SUPPORTED ENOTSUP   /* Operation Not Supported.  */
#else
  #define ERROR_NOT_SUPPORTED ENOSYS    /* Function Not Implemented. */
#endif


/* -------------------------------------------------------------------------- **
 * Global Constants
 */

const char *const weka_xattr_db_mod_name = "weka_xattr_db";


/* -------------------------------------------------------------------------- **
 * Typedefs
 *
 *  db_handle - Open database handle, with database state information and so.
 */

typedef struct
  {
  int                     db_sock;      /* The database socket.           */
  struct sockaddr_storage sa;           /* The address of the db server.  */
  uint8_t                 bufr[BSIZE];  /* Input line buffer.             */
  uint8_t                 bLen;         /* Bytes of <bufr> in use.        */
  } db_handle;


/* -------------------------------------------------------------------------- **
 * Static Functions
 */

static void DBG_dumpidx( const int dbglvl, const DATA_BLOB *idxblob )
  /* Debugging code.
   */
  {
  char   *p   = (char *)idxblob->data;
  size_t  pos = 0;

  if( (NULL == idxblob->data) || (idxblob->length < 1) )
    {
    DEBUGADD( dbglvl, ( "weka> Current index: <empty>\n" ) );
    return;
    }

  DEBUGADD( dbglvl, ( "weka> Current index (len %d):\n", idxblob->length ) );
  while( pos < idxblob->length )
    {
    DEBUGADD( dbglvl, ( "  %s\n", (p + pos) ) );
    pos += 1 + strlen( (p + pos) );
    }
  } /* DBG_dumpidx */

static int get_file_id( struct vfs_handle_struct *handle,
                        const char               *path,
                        struct file_id           *id )
  /** Given a file path, figure out the file ID.
   *  @param  [in] handle - The VFS connection structure.
   *  @param  [in] path   - File path (not sure if this is in Windows or
   *                        POSIX format at this point...but it wouldn't
   *                        be hard to find out).
   *  @param [out] id     - A pointer to the internal file ID that can be
   *                        used to perform further operations.
   *
   *  @returns  The return value is zero (0) on success, else -1.
   *
   *  \b Errors
   *  - ENOMEM is returned in <errno> if the talloc(3) subsystem was not able
   *    to allocate memory for use within the function.
   */
  {
  int                  ret   = -1;
  TALLOC_CTX          *frame = talloc_stackframe();
  struct smb_filename *smb_fname;

  errno = 0;
  smb_fname = synthetic_smb_fname( frame, path, NULL, NULL, 0 );
  if( smb_fname == NULL )
    {
    errno = ENOMEM;
    }
  else
    {
    if( 0 == SMB_VFS_NEXT_STAT( handle, smb_fname ) )
      {
      *id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, &smb_fname->st );
      ret = 0;
      }
    }

  TALLOC_FREE( frame );
  return( ret );
  } /* get_file_id */

static bool openDBSock( const char *srvSpec, db_handle *dbh )
  /**
   */
  {
  TALLOC_CTX      *frame = talloc_stackframe();
  int              rslt;
  int              sock;
  char            *srvHost;
  char            *srvPort;
  struct addrinfo  hints;
  struct addrinfo *srvInfo;
  struct addrinfo *p = NULL;

  /* Safety check. */
  if( NULL == frame )
    {
    DEBUG( 0, ( "talloc_stackframe(); Memory allocation failure.\n" ) );
    return( false );
    }

  /* Duplicate the input string so we can mess with it. */
  if( !(srvHost = talloc_strdup( frame, srvSpec )) )
    {
    DEBUG( 0, ( "talloc_strdup(); Memory allocation failure.\n" ) );
    TALLOC_FREE( frame );
    return( false );
    }

  /* Parse the address string into host and port. */
  if( NULL != (srvPort = strrchr( srvHost, ':' )) )
    *srvPort++ = '\0';
  else
    srvPort = DEF_PORT_STR;

  /* Do a lookup to get an actual address record. */
  (void)memset( &hints, 0, sizeof( hints ) );
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  rslt = getaddrinfo( srvHost, srvPort, &hints, &srvInfo );
  if( rslt )
    {
    DEBUG( 0, ( "%s, getaddrinfo: %s\n", srvSpec, gai_strerror( rslt ) ) );
    TALLOC_FREE( frame );
    return( false );
    }

  /* Allocate a socket.
   *  Should we be doing this per srvInfo[] entry?  Ugh.
   */
  sock = socket( hints.ai_family, hints.ai_socktype, 0 );
  if( sock < 0 )
    {
    DEBUG( 0, ( "Unable to allocate a socket; %s\n", strerror( errno ) ) );
    freeaddrinfo( srvInfo );
    TALLOC_FREE( frame );
    return( false );
    }

  /* Go through the list of returned results.
   *  Connect to the first one that works.
   */
  for( p = srvInfo; p != NULL; p = p->ai_next )
    {
    if( connect( sock, p->ai_addr, p->ai_addrlen ) >= 0 )
      {
      /* Got one.  Clean up and go home. */
      dbh->db_sock = sock;
      (void)memcpy( &(dbh->sa), &(p->ai_addr), p->ai_addrlen );
      freeaddrinfo( srvInfo );
      TALLOC_FREE( frame );
      return( true );
      }
    }

  /* No luck. */
  DEBUG( 0, ( "Unable to connect to %s.\n", srvSpec ) );
  close( sock );
  freeaddrinfo( srvInfo );
  TALLOC_FREE( frame );
  return( false );
  } /* openDBSock */

static int enc64( const unsigned char *src,
                  const size_t         slen,
                  char                *dst,
                  const size_t         dlen )
  {
  int               si, di;
  int               rslt;
  unsigned char     x[3];
  static const char encoding[] =
    {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
    };

  /* Figure out how big <*dst> must be for this to work.
   *  Remember we need one byte for the NUL terminator.
   */
  rslt = ENC64LEN( slen );
  if( dlen <= rslt )
    return( -1 );

  /* Encode. */
  for( si = di = 0; si < slen; /*-*/ )
    {
    x[0] = src[si++];
    x[1] = (si < slen) ? src[si++] : 0;
    x[2] = (si < slen) ? src[si++] : 0;

    dst[di++] = encoding[ (x[0] >> 2) & 0x3F ];
    dst[di++] = encoding[ ((x[0] & 0x03) << 4) | ((x[1] & 0xF0) >> 4) ];
    if( di < dlen )
      {
      dst[di++] = encoding[ ((x[1] & 0x0F) << 2) | ((x[2] & 0xC0) >> 6) ];
      if( di < dlen )
        dst[di++] = encoding[ (x[2] & 0x3F) ];
      }
    }

  dst[rslt] = '\0';
  return( rslt );
  } /* enc64 */

static int dec64( const char    *src,
                  const size_t   slen,
                  unsigned char *dst,
                  const size_t   dlen )
  {
  int               si, di;
  int               rslt;
  char              x[4];
  static const char decoding[80] =
    {
    62,  -1,  -1,  -1,  63,  52,  53,  54,  /* + , - . / 0 1 2  */
    55,  56,  57,  58,  59,  60,  61,  -1,  /* 3 4 5 6 7 8 9 :  */
    -1,  -1,  -1,  -1,  -1,  -1,   0,   1,  /* ; < = > ? @ A B  */
     2,   3,   4,   5,   6,   7,   8,   9,  /* C D E F G H I J  */
    10,  11,  12,  13,  14,  15,  16,  17,  /* K L M N O P Q R  */
    18,  19,  20,  21,  22,  23,  24,  25,  /* S T U V W X Y Z  */
    -1,  -1,  -1,  -1,  -1,  -1,  26,  27,  /* [ \ ] ^ _ ` a b  */
    28,  29,  30,  31,  32,  33,  34,  35,  /* c d e f g h i j  */
    36,  37,  38,  39,  40,  41,  42,  43,  /* k l m n o p q r  */
    44,  45,  46,  47,  48,  49,  50,  51   /* s t u v w x y z  */
    };

  rslt = DEC64LEN( slen );
  if( dlen < rslt )
    return( -1 );

  /* Decode. */
  for( si = di = 0; si < slen; /*-*/ )
    {
    x[0] = decoding[ src[si++] - 43 ];
    x[1] = (si < slen) ? decoding[ src[si++] - 43 ] : 0;
    x[2] = (si < slen) ? decoding[ src[si++] - 43 ] : 0;
    x[3] = (si < slen) ? decoding[ src[si++] - 43 ] : 0;

    dst[di++] = ((x[0] & 0x3F) << 2) | ((x[1] & 0x30) >> 4);
    if( di < dlen )
      {
      dst[di++] = ((x[1] & 0x0F) << 4) | ((x[2] & 0x3C) >> 2);
      if( di < dlen )
        dst[di++] = ((x[2] & 0x03) << 6) | (x[3] & 0x3F);
      }
    }
  return( rslt );
  } /* dec64 */

static void compose_key( TALLOC_CTX           *mem_ctx,
                         DATA_BLOB            *blob,
                         const struct file_id *id,
                         const char           *name )
  /*
   */
  {
  int    rslt;
  size_t idlen   = sizeof( struct file_id );
  size_t namelen = (NULL == name ) ? 0 : strlen( name );

  /* Prepare the data blob to receive the encoded poo.
   */
  blob->length = ENC64LEN( idlen + namelen ) + 1;
  blob->data   = (uint8_t *)talloc_size( mem_ctx, blob->length );
  if( NULL == blob->data )
    {
    blob->length = 0;
    return;
    }

  /* Encode the file_id portion of the key. */
  rslt = enc64( (unsigned char *)id, idlen, (char *)blob->data, blob->length );
  if( rslt < 0 )
    {
    data_blob_free( blob );
    return;
    }

  /* Encode the name portion of the key, if it exists. */
  if( namelen )
    {
    uint8_t *p = &(blob->data[rslt]);
    size_t   s = blob->length - rslt;

    if( enc64( (unsigned char *)name, namelen, (char *)p, s ) < 0 )
      {
      data_blob_free( blob );
      return;
      }
    }
  } /* compose_key */

static void compose_val( TALLOC_CTX  *mem_ctx,
                         DATA_BLOB   *blob,
                         const void  *value,
                         const size_t val_size )
  {
  int rslt;

  /* Prepare the data blob to receive the encoded poo.
   */
  blob->length = ENC64LEN( val_size ) + 1;
  blob->data   = (uint8_t *)talloc_size( mem_ctx, blob->length );
  if( NULL == blob->data )
    {
    blob->length = 0;
    return;
    }

  /* Encode the value.
   */
  rslt = enc64( (unsigned char *)value, val_size,
                (char *)blob->data, blob->length );
  if( rslt < 0 )
    data_blob_free( blob );

  /* Finished, for good or ill. */
  return;
  } /* compose_val */

static ssize_t db_request( db_handle *dbh, TALLOC_CTX *mem_ctx, char *fmt, ... )
  {
  va_list ap;
  char   *msg;

  errno = 0;
  va_start( ap, fmt );
  msg = talloc_vasprintf( mem_ctx, fmt, ap );
  va_end( ap );
  if( NULL == msg )
    {
    errno = ENOMEM;
    return( -1 );
    }
  return( write( dbh->db_sock, msg, strlen( msg ) ) );
  } /* db_request */

static ssize_t db_readln( db_handle *dbh )
  {
  uint8_t c[1];
  ssize_t rslt;

  for( dbh->bLen = 0; (dbh->bLen < (BSIZE-1)); dbh->bLen++ )
    {
    if( 1 != (rslt = read( dbh->db_sock, c, 1 )) )
      break;
    else
      {
      dbh->bufr[dbh->bLen] = (uint8_t)c[0];
      if( '\n' == c[0] )
        {
        dbh->bLen++;
        break;
        }
      }
    }
  dbh->bufr[dbh->bLen] = '\0';
  if( rslt < 0 )
    return( -1 );
  return( dbh->bLen );
  } /* db_readln */

static void db_find_end( db_handle *dbh )
  {
  char *match = "END\r\n";

  while( strncmp( match, dbh->bufr, 5 ) )
    {
    /* On error or eoinput, our only option is to bail out. */
    if( db_readln( dbh ) <= 0 )
      break;
    }
  dbh->bLen = 0;
  dbh->bufr[0] = '\0';
  return;
  } /* db_find_end */

static int db_scanf( db_handle *dbh, char *fmt, ... )
  {
  va_list ap;
  int     rslt;

  if( db_readln( dbh ) < 0 )
    return( false );
  va_start( ap, fmt );
  rslt = vsscanf( dbh->bufr, fmt, ap );
  va_end( ap );
  return( rslt );
  } /* db_scanf */

static DATA_BLOB db_readval( db_handle *dbh, TALLOC_CTX *mem_ctx, int val_len )
  {
  int       rslt;
  uint8_t   c[2];         /* Scratch space.        */
  DATA_BLOB encblob[1];   /* Blob of encoded data. */
  DATA_BLOB decblob[1];   /* Blob of decoded data. */

  /* Prep the encoding blob. */
  encblob->length = (size_t)val_len;
  encblob->data   = (uint8_t *)talloc_size( mem_ctx, encblob->length );
  if( NULL == encblob->data )
    {
    encblob->length = 0;
    return( *encblob );
    }

  /* Read the specified number of bytes. */
  if( read( dbh->db_sock, encblob->data, encblob->length ) != encblob->length )
    data_blob_free( encblob );

  /* Consume the terminating "\r\n". */
  if( (read( dbh->db_sock, c, 2 ) < 2) || ('\r' != *c) )
    data_blob_free( encblob );
  /* Consume what we hope is the "END\r\n" line. */
  (void)db_find_end( dbh );

  /* If we don't have correct input, give up now. */
  if( !(encblob->length) )
    return( *encblob );

  /* We should have a good encoded blob now.
   *  Let's make some space and decode it.
   */
  decblob->length = DEC64LEN( encblob->length );
  decblob->data   = (uint8_t *)talloc_size( mem_ctx, decblob->length );
  if( NULL == decblob->data )
    {
    data_blob_free( encblob );
    return( *encblob );
    }

  rslt = dec64( encblob->data, encblob->length,
                decblob->data, decblob->length );
  if( rslt < 0 )
    data_blob_free( decblob );

  data_blob_free( encblob );
  return( *decblob );
  } /* db_readval */

static ssize_t db_getattr( db_handle            *dbh,
                           TALLOC_CTX           *mem_ctx,
                           const struct file_id *id,
                           const char           *name,
                           DATA_BLOB            *blob )
  /* Get an extended attribute from a file.
   *
   *  Output: Returns -1 on error, otherwise the size of the retrieved
   *          and decoded data, in bytes, is returned.
   *          - The most likely error is that the key wasn't found.
   */
  {
  int tmpint;

  /* Compose and send the get request.
   */
  compose_key( mem_ctx, blob, id, name );
  db_request( dbh, mem_ctx, "get %s\r\n", blob->data );
  data_blob_free( blob );

  /* Read the first line of the response, looking for a positive result.
   */
  if( db_scanf( dbh, "VALUE %*s 0 %d\r\n", &tmpint ) < 1 )
    return( -1 );

  /* Now we know the size of the value we can read it, decode it
   * and return its length.
   */
  *blob = db_readval( dbh, mem_ctx, tmpint );
  return( (blob->length) ? (blob->length) : -1 );
  } /* db_getattr */

static int db_setattr( db_handle            *dbh,
                       const struct file_id *id,
                       const char           *name,
                       const void           *value,
                       size_t                val_size,
                       int                   flags )
  /* Set an extended attribute on a file.
   *
   * This is a function that needs major redesign and streamlining if it were
   * ever to go into a production system.  Oh... and we would want either
   * record locking or transactions.
   */
  {
  TALLOC_CTX *frame = talloc_stackframe();
  DATA_BLOB   keyblob[1];
  DATA_BLOB   valblob[1];
  DATA_BLOB   encblob[1];
  char       *cmd;
  size_t      len;
  int         rslt;

  /* Compose the set/add/replace command.
   */
  flags &= (XATTR_CREATE | XATTR_REPLACE);
  cmd = flags ? ((flags & XATTR_REPLACE) ? "replace" : "add") : "set";
  compose_key( frame, keyblob, id, name );
  compose_val( frame, valblob, value, val_size );
  if( (NULL == keyblob->data) || (NULL == valblob->data) )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Send the command (then do a little cleanup).
   */
  db_request( dbh, frame, "%s %s 0 0 %d\r\n%s\r\n", cmd,
              keyblob->data, (valblob->length)-1, valblob->data );

  /* Now look for and interpret the response.
   */
  if( (db_readln( dbh ) < 0) || strncmp( "STORED", dbh->bufr, 6 ) )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  DEBUG( 0, ( "weka> Stored key <%s>\n", name ) );

  /* Is the name already indexed?  If so, the update has concluded successfuly.
   */
  if( flags & XATTR_REPLACE )
    {
    TALLOC_FREE( frame );
    return( 0 );
    }

  /* We will need to update the index.  First step, grab the index.
   *  Optimally, we would lock the index record until the update is complete.
   */
  data_blob_free( keyblob );
  data_blob_free( valblob );
  compose_key( frame, keyblob, id, NULL );
  if( NULL == keyblob->data )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }
  db_request( dbh, frame, "get %s\r\n", keyblob->data );

  /* Read the first line of the response.
   *  Note: If the db_scanf() fails, it *probably* means that the index
   *        has not yet been initialized.  We'll create a new one.
   */
  if( db_scanf( dbh, "VALUE %*s 0 %d\r\n", &len ) > 0 )
    {
    /* The index exists, and we have it's encoded length.
     *  Read it in.
     */
    *valblob = db_readval( dbh, frame, len );
    if( NULL == valblob->data )
      {
      TALLOC_FREE( frame );
      return( -1 );
      }

    /* If we performed an "add" operation, then we *know* that the name is not
     * (shouldn't be) in the index.  Otherwise, we have to check.  If we find
     * the name in the index, then we don't need to update it, so we're done.
     */
    if( !(flags & XATTR_CREATE) )
      {
      size_t  pos = 0;
      char   *p   = (char *)valblob->data;

      while( pos < valblob->length )
        {
        if( 0 == strcmp( p, name ) )
          {
          TALLOC_FREE( frame );
          return( 0 );  /* We're done.  Yay!  */
          }
        pos += strlen( p ) + 1;
        p = (char *)&(valblob->data[pos]);
        }
      }
    }

  /* We know for sure that the name isn't in the list, so we can add it.
   */
  len = valblob->length + strlen( name ) + 1;
  DEBUG( 0, ( "weka> [Re]Allocating valblob; len = %d\n", len ) );
  valblob->data = talloc_realloc_size( frame, valblob->data, len );

  if( NULL == valblob->data )
    {
    /* Sigh... after all that work... */
    DEBUG( 0, ( "weka> talloc_realloc_size() failed on index update.\n" ) );
    TALLOC_FREE( frame );
    return( -1 );
    }
  /* This memcpy() includes the terminating NUL byte of the new name. */
  (void)memcpy( &(valblob->data[valblob->length]), name, strlen( name ) + 1 );
  valblob->length = len;
  /* Now re-encode it. */
  encblob->length = ENC64LEN( len ) + 1;
  encblob->data = (uint8_t *)talloc_size( frame, encblob->length );
  rslt = enc64( valblob->data, valblob->length,
                encblob->data, encblob->length );
  if( rslt < 0 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }
  /* Now re-save it. */
  db_request( dbh, frame, "set %s 0 0 %d\r\n%s\r\n",
              keyblob->data, (encblob->length)-1, encblob->data );
  /* ...and here is where we would unlock the index record, if we could. */
  if( (db_readln( dbh ) < 0) || strncmp( "STORED", dbh->bufr, 6 ) )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  DEBUG( 2, ( "weka> Added <%s> to the index:\n", name ) );
  DBG_dumpidx( 2, valblob );  /* Dump the current index to the logfile. */

  /* Phew!  */
  TALLOC_FREE( frame );
  return( 0 );
  } /* db_setattr */

static ssize_t db_listattr( db_handle            *dbh,
                            const struct file_id *id,
                            char                 *list,
                            size_t                lst_size )
  /* Retrieve the attribute index.
   */
  {
  TALLOC_CTX *frame = talloc_stackframe();
  DATA_BLOB   blob[1];
  int         tmpint;

  errno = 0;

  compose_key( frame, blob, id, NULL );
  if( NULL == blob->data )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }
  db_request( dbh, frame, "get %s\r\n", blob->data );

  /* Read the first line of the response.
   */
  if( db_scanf( dbh, "VALUE %*s 0 %d\r\n", &tmpint ) < 1 )
    {
    /* No match.  Return an empty list. */
    TALLOC_FREE( frame );
    *list = '\0';
    return( 0 );
    }

  /* We know the size of the index blob, so we can read it and decode it.
   *  Note: We *must* do this because the value is stuck in the input stream.
   *        Reading it is the easiest way to clear the stream.
   */
  data_blob_free( blob );
  *blob = db_readval( dbh, frame, tmpint );
  if( NULL == blob->data )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Do we have enough room in <list> to return the list?
   */
  if( tmpint > lst_size )
    {
    TALLOC_FREE( frame );
    errno = ERANGE;
    return( tmpint );
    }

  (void)memcpy( list, blob->data, blob->length );
  TALLOC_FREE( frame );
  return( blob->length );
  } /* db_listattr */

static int db_removeattr( db_handle            *dbh,
                          const struct file_id *id,
                          const char           *name )
  /* Remove an attribute and update the index.
   */
  {
  TALLOC_CTX *frame = talloc_stackframe();
  DATA_BLOB   keyblob[1];
  DATA_BLOB   idxblob[1];
  bool        deleted;
  bool        idxupdate;
  uint8_t    *p;
  size_t      pos;
  size_t      slen;
  int         tmpint;

  errno = 0;

  /* Generate the key for the attribute, and delete it.
   */
  compose_key( frame, keyblob, id, name );
  if( NULL == keyblob->data )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }
  db_request( dbh, frame, "delete %s\r\n", keyblob->data );

  /* Check the result.
   *  If it wasn't there to be deleted, we need to return an error code,
   *  so we keep track of the result.
   */
  deleted = true;
  if( (db_readln( dbh ) < 0) || strncmp( "DELETED", dbh->bufr, 7 ) )
    deleted = false;
  data_blob_free( keyblob );

  /* Now we need to delete the entry in the index.
   */
  compose_key( frame, keyblob, id, NULL );
  if( NULL == keyblob->data )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }
  db_request( dbh, frame, "get %s\r\n", keyblob->data );

  /* Read the first line of the response.
   */
  if( db_scanf( dbh, "VALUE %*s 0 %d\r\n", &tmpint ) < 1 )
    {
    /* No match.  Give up. */
    TALLOC_FREE( frame );
    return( 0 );
    }

  /* Read and decode the index blob.
   */
  *idxblob = db_readval( dbh, frame, tmpint );
  if( NULL == idxblob->data )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Remove the entry we no longer want.
   */
  idxupdate = false;
  p         = idxblob->data;
  pos       = 0;
  while( pos < idxblob->length )
    {
    slen = strlen( p ) + 1;
    pos += slen;
    if( 0 == strcmp( p, name ) )
      {
      (void)memmove( p, p+slen, (idxblob->length - pos) );
      (idxblob->length) -= slen;
      idxupdate = true;
      break;
      }
    p += slen;
    }

  /* Store the result, if it was changed.
   */
  if( idxupdate )
    {
    DATA_BLOB encblob[1];

    encblob->length = ENC64LEN( idxblob->length ) + 1;
    encblob->data   = talloc_size( frame, encblob->length );
    if( NULL != encblob->data )
      {
      tmpint = enc64( idxblob->data, idxblob->length,
                      encblob->data, encblob->length );
      if( tmpint < 0 )
        {
        TALLOC_FREE( frame );
        return( -1 );
        }
      /* Now re-save it. */
      db_request( dbh, frame, "set %s 0 0 %d\r\n%s\r\n",
                  keyblob->data, (encblob->length)-1, encblob->data );
      if( (db_readln( dbh ) < 0) || strncmp( "STORED", dbh->bufr, 6 ) )
        {
        TALLOC_FREE( frame );
        return( -1 );
        }
      }
    }

  TALLOC_FREE( frame );
  if( !deleted )
    {
    errno = ENOATTR;
    return( -1 );
    }
  return( 0 );
  } /* db_removeattr */

static void db_remove_all_attrs( db_handle            *dbh,
                                 const struct file_id *id )
  /* Remove all attributes assigned to a file.
   */
  {
  TALLOC_CTX *frame = talloc_stackframe();
  DATA_BLOB   keyblob[1];
  DATA_BLOB   idxblob[1];
  int         tmpint;
  ssize_t     pos;

  /* Retrieve the index.
   */
  compose_key( frame, keyblob, id, NULL );
  if( NULL == keyblob->data )
    {
    TALLOC_FREE( frame );
    return;
    }
  db_request( dbh, frame, "get %s\r\n", keyblob->data );

  /* Read the first line of the response.
   */
  if( db_scanf( dbh, "VALUE %*s 0 %d\r\n", &tmpint ) < 1 )
    {
    TALLOC_FREE( frame );
    return;
    }

  /* Read and decode the index blob.
   */
  *idxblob = db_readval( dbh, frame, tmpint );
  if( NULL == idxblob->data )
    {
    TALLOC_FREE( frame );
    return;
    }

  /* Delete the index.
   *  We no longer need the database copy of the index.
   */
  db_request( dbh, frame, "delete %s\r\n", keyblob->data );
  (void)db_readln( dbh );   /* Consume but ignore the response. */

  DEBUG( 0, ( "weka> Deleting index, got: %s", dbh->bufr ) );

  /* For each index entry, delete the attribute.
   */
  for( pos = 0; pos < idxblob->length; /*-*/ )
    {
    data_blob_free( keyblob );
    compose_key( frame, keyblob, id, &(idxblob->data[pos]) );
    if( NULL != keyblob->data )
      {
      db_request( dbh, frame, "delete %s\r\n", keyblob->data );
      (void)db_readln( dbh );
      DEBUG( 0, ( "weka> Deleted idx entry %s, got: %s",
                  &(idxblob->data[pos]), dbh->bufr ) );
      }
    pos += strlen( &(idxblob->data[pos]) ) + 1;
    }

  TALLOC_FREE( frame );
  return;
  } /* db_remove_all_attrs */


/* -------------------------------------------------------------------------- **
 * VFS Functions
 */

static ssize_t weka_xattr_db_getxattr( struct vfs_handle_struct *handle,
                                       const char               *path,
                                       const char               *name,
                                       void                     *value,
                                       const size_t              val_size )
  /** Given a file path, look up an xattr value given a key (name).
   *
   *  @param  [in] handle   The VFS handle for this connection.
   *  @param  [in] path     The file path.
   *  @param  [in] name     The key to be retrieved.
   *  @param [out] value    A pointer to a buffer into which the recovered
   *                        value will be written.
   *  @param  [in] val_size The size, in bytes of the buffer indicated by
   *                        <value>.
   *  @returns  On success, the size (in bytes) of the returned value is
   *            returned.  On error, -1 is returned and <errno> is set to
   *            one of the following values:
   *            - 0 (zero); No error code returned.  (Something went wrong
   *                        but we're not telling you what it was.)
   *            - ENOATTR;  Key not found.
   *            - ERANGE;   The size of <value>, as given in <val_size> is
   *                        not large enough to receive the stored value.
   */
  {
  int             ret;
  ssize_t         xattr_size;
  DATA_BLOB       blob[1];
  struct file_id  id;
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Getting xatter %s on [%s]\n", name, path ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Find/create the file ID. */
  ret = get_file_id( handle, path, &id );
  if( ret == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Retrieve the value, if it exists. */
  xattr_size = db_getattr( dbh, frame, &id, name, blob );
  if( xattr_size < 0 )
    {
    TALLOC_FREE( frame );
    errno = ENOATTR;
    return( -1 );
    }

  /* Do we have room to copy the value into the */
  if( blob->length > val_size )
    {
    TALLOC_FREE( frame );
    errno = ERANGE;
    return( -1 );
    }

  /* Copy out the data. */
  (void)memcpy( value, blob->data, xattr_size );
  TALLOC_FREE( frame );
  return( xattr_size );
  } /* weka_xattr_db_getxattr */

static ssize_t weka_xattr_db_fgetxattr( struct vfs_handle_struct *handle,
                                        struct files_struct      *fsp,
                                        const char               *name,
                                        void                     *value,
                                        size_t                    val_size )
  /** Given an open file, look up an xattr value given a key (name).
   *
   *  @param  [in] handle   The VFS handle for this connection.
   *  @param  [in] fsp      Pointer to a Samba file handle structure.
   *  @param  [in] name     The key to be retrieved.
   *  @param [out] value    A pointer to a buffer into which the recovered
   *                        value will be written.
   *  @param  [in] val_size The size, in bytes of the buffer indicated by
   *                        <value>.
   *  @returns  On success, the size (in bytes) of the returned value is
   *            returned.  On error, -1 is returned and <errno> is set to
   *            one of the following values:
   *            - 0 (zero); No error code returned.  (Something went wrong
   *                        but we're not telling you what it was.)
   *            - ENOATTR;  Key not found.
   *            - ERANGE;   The size of <value>, as given in <val_size> is
   *                        not large enough to receive the stored value.
   */
  {
  ssize_t         xattr_size;
  SMB_STRUCT_STAT sbuf[1];
  DATA_BLOB       blob[1];
  struct file_id  id;
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Fgetting xatter %s on opened file.\n", name ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( SMB_VFS_NEXT_FSTAT( handle, fsp, sbuf ) == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }
  id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, sbuf );

  xattr_size = db_getattr( dbh, frame, &id, name, blob );
  if( xattr_size < 0 )
    {
    errno = ENOATTR;
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( blob->length > val_size )
    {
    TALLOC_FREE( frame );
    errno = ERANGE;
    return( -1 );
    }

  memcpy( value, blob->data, xattr_size );
  TALLOC_FREE( frame );
  return( xattr_size );
  } /* weka_xattr_db_fgetxattr */

static int weka_xattr_db_setxattr( struct vfs_handle_struct *handle,
                                   const char               *path,
                                   const char               *name,
                                   const void               *value,
                                   size_t                    val_size,
                                   int                       flags )
  /** Given a file path, set an extended attribute.
   *
   *  @param  [in] handle   The VFS handle for this connection.
   *  @param  [in] path     The file path.
   *  @param  [in] name     The key of the xattr to be set.
   *  @param [out] value    A pointer to a buffer that contains the xattr
   *                        value.
   *  @param  [in] val_size The size, in bytes, of the contents of <value>.
   *  @param  [in] flags    One of three values:
   *                        - \b Zero (0): Unconditionally set the value.
   *                        - \b XATTR_CREATE: Only set the value if the
   *                          xattr does not already exist.  That is,
   *                          create a new xattr.
   *                        - \b XATTR_REPLACE: Only set the value if the
   *                          xattr already exists.
   *
   *  @returns  Zero (0) on success, -1 on error.
   *            The value of <errno> may provide some insight. ...or not.
   */
  {
  struct file_id  id;
  db_handle      *dbh;
  int             ret;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Setting xatter %s on [%s]\n", name, path ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( get_file_id( handle, path, &id ) < 0 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  ret = db_setattr( dbh, &id, name, value, val_size, flags );
  TALLOC_FREE( frame );
  return( ret );
  } /* weka_xattr_db_setxattr */

static int weka_xattr_db_fsetxattr( struct vfs_handle_struct *handle,
                                    struct files_struct      *fsp,
                                    const char               *name,
                                    const void               *value,
                                    size_t                    val_size,
                                    int                       flags )
  /** Given an open file, set an extended attribute on the file.
   *
   *  @param  [in] handle   The VFS handle for this connection.
   *  @param  [in] fsp      Pointer to a Samba file handle structure.
   *  @param  [in] name     The key of the xattr to be set.
   *  @param [out] value    A pointer to a buffer that contains the xattr
   *                        value.
   *  @param  [in] val_size The size, in bytes, of the contents of <value>.
   *  @param  [in] flags    One of three values:
   *                        - \b Zero (0): Unconditionally set the value.
   *                        - \b XATTR_CREATE: Only set the value if the
   *                          xattr does not already exist.  That is,
   *                          create a new xattr.
   *                        - \b XATTR_REPLACE: Only set the value if the
   *                          xattr already exists.
   *
   *  @returns  Zero (0) on success, -1 on error.
   *            The value of <errno> may provide some insight. ...or not.
   */
  {
  int             ret;
  struct file_id  id;
  SMB_STRUCT_STAT sbuf[1];
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Fsetting xatter %s on opened file.\n", name ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( SMB_VFS_NEXT_FSTAT( handle, fsp, sbuf ) == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, sbuf );

  ret = db_setattr( dbh, &id, name, value, val_size, flags );
  TALLOC_FREE( frame );
  return( ret );
  } /* weka_xattr_db_fsetxattr */

static ssize_t weka_xattr_db_listxattr( struct vfs_handle_struct *handle,
                                        const char               *path,
                                        char                     *list,
                                        size_t                    lst_size )
  /** Given a file path, list the keys of existing xattrs.
   *
   *  @param  [in] handle   The VFS handle for this connection.
   *  @param  [in] path     The file path.
   *  @param [out] list     A buffer into which to write the list of
   *                        keys.
   *  @param  [in] lst_size Bytes available in <list>.
   *
   *  @returns  On error, -1 is returned.  On success, size of the list, in
   *            bytes, is returned.
   */
  {
  struct file_id  id;
  int             ret;
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Listing xatters on [%s]\n", path ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  ret = get_file_id( handle, path, &id );
  if( -1 == ret )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  ret = db_listattr( dbh, &id, list, lst_size );
  TALLOC_FREE( frame );
  return( ret );
  } /* weka_xattr_db_listxattr */

static ssize_t weka_xattr_db_flistxattr( struct vfs_handle_struct *handle,
                                         struct files_struct      *fsp,
                                         char                     *list,
                                         size_t                    lst_size )
  /** Given an open file, list the keys of existing xattrs.
   *
   *  @param  [in] handle   The VFS handle for this connection.
   *  @param  [in] fsp      Pointer to a Samba file handle structure.
   *  @param [out] list     A buffer into which to write the list of
   *                        keys.
   *  @param  [in] lst_size Bytes available in <list>.
   *
   *  @returns  On error, -1 is returned.  On success, size of the list in
   *            bytes is returned.
   */
  {
  int             ret;
  struct file_id  id;
  SMB_STRUCT_STAT sbuf;
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Flisting xatters on an opened file.\n" ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( SMB_VFS_NEXT_FSTAT( handle, fsp, &sbuf ) < 0 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, &sbuf );

  ret = db_listattr( dbh, &id, list, lst_size );
  TALLOC_FREE( frame );
  return( ret );
  } /* weka_xattr_db_flistxattr */

static int weka_xattr_db_removexattr( struct vfs_handle_struct *handle,
                                      const char               *path,
                                      const char               *name )
  /** Given a file path, delete an associated xattr.
   */
  {
  int             ret;
  struct file_id  id;
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Removing xatter %s on [%s]\n", name, path ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( get_file_id( handle, path, &id ) < 0 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  ret = db_removeattr( dbh, &id, name );
  TALLOC_FREE( frame );
  return( ret );
  } /* weka_xattr_db_removexattr */

static int weka_xattr_db_fremovexattr( struct vfs_handle_struct *handle,
                                       struct files_struct      *fsp,
                                       const char               *name )
  /** Given an open file, delete an associated xattr.
   */
  {
  int             ret;
  SMB_STRUCT_STAT sbuf;
  struct file_id  id;
  db_handle      *dbh;
  TALLOC_CTX     *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Fremoving xatter %s on an opened file.\n", name ) );

  errno = 0;
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( SMB_VFS_NEXT_FSTAT( handle, fsp, &sbuf ) < 0 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, &sbuf );

  ret = db_removeattr( dbh, &id, name );
  TALLOC_FREE( frame );
  return( ret );
  } /* weka_xattr_db_fremovexattr */

static int weka_xattr_db_open( vfs_handle_struct   *handle,
                               struct smb_filename *smb_fname,
                               files_struct        *fsp,
                               int                  flags,
                               mode_t               mode )
  /**
   */
  {
  int         ret;
  db_handle  *dbh   = NULL;

  DEBUG( 0, ( "weka> Opening file %s.\n", smb_fname_str_dbg( smb_fname ) ) );

  /* Call down the VFS stack to open/create the file. */
  fsp->fh->fd = SMB_VFS_NEXT_OPEN( handle, smb_fname, fsp, flags, mode );
  if( fsp->fh->fd < 0 )
    return( fsp->fh->fd );

  /* If we did not create a new file, then we are finished here. */
  if( (flags & (O_CREAT|O_EXCL)) != (O_CREAT|O_EXCL) )
    {
    char *tmpstr = (flags & (O_CREAT|O_EXCL)) ?
                            (flags & O_CREAT) ? "O_CREAT" : "O_EXCL"
                                              : "!O_CREAT !O_EXCL";

    return( fsp->fh->fd );
    }

  DEBUG( 0, ( "weka> New file %s created; clearing old xattrs.\n",
              smb_fname_str_dbg( smb_fname ) ) );

  /* We know we used O_CREAT|O_EXCL and it worked, so we must have created
   * a new file.  The rest of this function simply ensures that no left-over
   * xattrs (from a previous incarnation of the file) exist in the database.
   */
  if( SMB_VFS_FSTAT( fsp, &smb_fname->st ) < 0 )
    {
    /* In theory, this can't happen... */
    DBG_WARNING( "SMB_VFS_FSTAT failed on file %s (%s)\n",
                 smb_fname_str_dbg( smb_fname ),
                 strerror( errno ) );
    return( -1 );
    }

  fsp->file_id = SMB_VFS_FILE_ID_CREATE( fsp->conn, &smb_fname->st );

  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    return( -1 );

  db_remove_all_attrs( dbh, &fsp->file_id );
  return( fsp->fh->fd );
  } /* weka_xattr_db_open */

static int weka_xattr_db_mkdir( vfs_handle_struct         *handle,
                                const struct smb_filename *smb_fname,
                                mode_t                     mode )
  /**
   */
  {
  db_handle           *dbh   = NULL;
  TALLOC_CTX          *frame = NULL;
  struct file_id       fileid;
  int                  ret;
  struct smb_filename *smb_fname_tmp = NULL;

  DEBUG( 0, ("weka> Creating directory %s\n", smb_fname_str_dbg( smb_fname )) );

  /* Create the directory first. */
  errno = 0;
  ret = SMB_VFS_NEXT_MKDIR( handle, smb_fname, mode );
  if( ret < 0 )
    return( ret );

  frame = talloc_stackframe();
  smb_fname_tmp = cp_smb_filename( frame, smb_fname );
  if( smb_fname_tmp == NULL )
    {
    TALLOC_FREE( frame );
    errno = ENOMEM;
    return( -1 );
    }

  /* Always use LSTAT here - we just created the directory.
   * [crh: I have no idea why Samba's LSTAT should be used here.]
   */
  ret = SMB_VFS_LSTAT( handle->conn, smb_fname_tmp );
  if( ret == -1 )
    {
    /* Rename race. Let upper level take care of it. */
    TALLOC_FREE( frame );
    return( -1 );
    }

  if( !S_ISDIR( smb_fname_tmp->st.st_ex_mode ) )
    {
    /* Rename race. Let upper level take care of it. */
    TALLOC_FREE( frame );
    return( -1 );
    }

  fileid = SMB_VFS_FILE_ID_CREATE( handle->conn, &smb_fname_tmp->st );

  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  db_remove_all_attrs( dbh, &fileid );
  TALLOC_FREE( frame );
  return( 0 );
  } /* weka_xattr_db_mkdir */

static int weka_xattr_db_unlink( vfs_handle_struct         *handle,
                                 const struct smb_filename *smb_fname )
  /** On unlink we need to delete the tdb record.
   */
  {
  int                  ret = -1;
  bool                 remove_record;
  struct file_id       id;
  db_handle           *dbh;
  struct smb_filename *smb_fname_tmp = NULL;
  TALLOC_CTX          *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Unlinking %s\n", smb_fname_str_dbg( smb_fname )) );

  /* Grab file information. */
  errno = 0;
  smb_fname_tmp = cp_smb_filename( frame, smb_fname );
  if( smb_fname_tmp == NULL )
    {
    TALLOC_FREE( frame );
    errno = ENOMEM;
    return( -1 );
    }

  /* Get fstat stuff. */
  if( smb_fname_tmp->flags & SMB_FILENAME_POSIX_PATH )
    ret = SMB_VFS_NEXT_LSTAT( handle, smb_fname_tmp );
  else
    ret = SMB_VFS_NEXT_STAT( handle, smb_fname_tmp );
  if( ret == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Now grab the DB handle */
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Only remove the record if we're removing the last link to the file. */
  remove_record = ( smb_fname_tmp->st.st_ex_nlink <= 1 ) ? true : false;

  /* Okay, now we can go ahead and unlink the file. */
  ret = SMB_VFS_NEXT_UNLINK( handle, smb_fname_tmp );
  if( ret == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* ...and now we clean up the database. */
  if( remove_record )
    {
    id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, &smb_fname_tmp->st );
    db_remove_all_attrs( dbh, &id );
    }

  TALLOC_FREE( frame );
  return( 0 );
  } /* weka_xattr_db_unlink */

static int weka_xattr_db_rmdir( vfs_handle_struct         *handle,
                                const struct smb_filename *smb_fname )
  /** On rmdir, we need to delete the associated database entries.
   */
  {
  SMB_STRUCT_STAT    sbuf;
  struct file_id     id;
  db_handle         *dbh;
  int                ret;
  TALLOC_CTX        *frame = talloc_stackframe();

  DEBUG( 0, ("weka> Removing directory %s\n", smb_fname_str_dbg( smb_fname )) );

  /* Get the database handle. */
  HANDLE_GET_DATA( handle, dbh, db_handle );
  if( NULL == dbh )
    {
    DEBUG( 0, ( "weka> How can handle->data be NULL here?\n" ) );
    TALLOC_FREE( frame );
    return( -1 );
    }
  if( vfs_stat_smb_basename( handle->conn, smb_fname, &sbuf ) == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* Generate the file_id structure.  */
  id = SMB_VFS_NEXT_FILE_ID_CREATE( handle, &sbuf );

  /* Remove that directory. */
  ret = SMB_VFS_NEXT_RMDIR( handle, smb_fname );
  if( ret == -1 )
    {
    TALLOC_FREE( frame );
    return( -1 );
    }

  /* If directory removal succeeded, we can remove the EAs. */
  db_remove_all_attrs( dbh, &id );

  TALLOC_FREE( frame );
  return( 0 );
  } /* weka_xattr_db_rmdir */


static void close_xattr_db( void **data )
  /** Destructor for the VFS private data.
   *
   *  @param [in,out] data  A pointer to < handle->data >.  We receive a
   *                        pointer to the pointer so that the pointer to
   *                        which we are pointing can be set to NULL.
   */
  {
  db_handle **p_dbHandle = (db_handle **)data;

  /* Close the connection, free the memory. */
  (void)write( (*p_dbHandle)->db_sock, "quit\r\n", 6 );
  (void)close( (*p_dbHandle)->db_sock );
  TALLOC_FREE( *p_dbHandle );
  DEBUG( 0, ( "weka> Closed tree connect.\n" ) );
  } /* close_xattr_db */

static int weka_xattr_db_connect( vfs_handle_struct *handle,
                                  const char        *service,
                                  const char        *user )
  /** Handle a Tree Connect event.
   *
   *  @param [in,out] handle  - Pointer to the VFS handle structure.
   *  @param [in]     service - The share name (not the path).
   *  @param [in]     user    - The username, which is passed down the
   *                            stack.
   *
   *  @returns  This function returns zero (0) on success, and a
   *            negative value on failure.
   *
   *  \b Notes
   *  - The external xattr database is opened on the Tree Connect.
   */
  {
  int         rslt, snum;
  char       *sname    = NULL;
  const char *tmpstr   = NULL;
  db_handle  *dbHandle = NULL;

  DEBUG( 0, ( "weka> Tree connect to service %s.\n", service ) );

  /* Call the next connect method down the stack.
   *  If it fails, just pass the error back up the stack.
   */
  errno = 0;
  if( (rslt = SMB_VFS_NEXT_CONNECT( handle, service, user )) < 0 )
    return( rslt );

  /* Allocate a database handle.
   */
  dbHandle = (db_handle *)talloc_zero( handle->conn, db_handle );
  if( NULL == dbHandle )
    {
    DEBUG( 0, ( "talloc_zero( handle->conn ); Memory allocation failure.\n" ) );
    return( -1 );
    }

  /* Get the database address from the smb.conf file.
   *  We are looking for the [<host>][:<port>] so that we can connect to
   *  the database server.
   */
  tmpstr = lp_parm_const_string( SNUM( handle->conn ),
                                 weka_xattr_db_mod_name,
                                 "db_server",
                                 NULL );
  if( NULL == tmpstr )
    {
    DEBUG( 0, ( "Please set the %s:db_server parameter in <smb.conf>.\n",
                weka_xattr_db_mod_name ) );
    TALLOC_FREE( dbHandle );
    return( -1 );
    }

  /* We need to have this snum (service number) value.
   */
  snum = find_service( talloc_tos(), service, &sname );
  if( snum == -1 || sname == NULL )
    {
    /* According to lore, this should never happen.
     * If it does, something's really wrong.
     */
    DEBUG( 0, ( "Could not find service number for %s.\n", service ) );
    TALLOC_FREE( dbHandle );
    return( -1 );
    }

  /* Open the connection to the database server.
   */
  if( !openDBSock( tmpstr, dbHandle ) )
    {
    lp_do_parameter( snum, "ea support", "False" );
    TALLOC_FREE( dbHandle );
    return( -1 );
    }

  /* Success...
   */
  lp_do_parameter( snum, "ea support", "True" );
  HANDLE_SET_DATA( handle, dbHandle, close_xattr_db );
  DEBUG( 0, ( "weka> DB Handle opened.\n" ) );
  return( 0 );
  } /* weka_xattr_db_connect */


/* -------------------------------------------------------------------------- **
 * Initialization
 *
 *  vfs_weka_xattr_db_fns - This is an instance of a <vfs_fn_pointers>
 *                          structure.  It will be pushed onto Samba's VFS
 *                          stack, and the listed functions will superceed
 *                          those further down the stack.
 */

static struct vfs_fn_pointers vfs_weka_xattr_db_fns =
  {
  .getxattr_fn     = weka_xattr_db_getxattr,
  .fgetxattr_fn    = weka_xattr_db_fgetxattr,
  .setxattr_fn     = weka_xattr_db_setxattr,
  .fsetxattr_fn    = weka_xattr_db_fsetxattr,
  .listxattr_fn    = weka_xattr_db_listxattr,
  .flistxattr_fn   = weka_xattr_db_flistxattr,
  .removexattr_fn  = weka_xattr_db_removexattr,
  .fremovexattr_fn = weka_xattr_db_fremovexattr,
  .open_fn         = weka_xattr_db_open,
  .mkdir_fn        = weka_xattr_db_mkdir,
  .unlink_fn       = weka_xattr_db_unlink,
  .rmdir_fn        = weka_xattr_db_rmdir,
  .connect_fn      = weka_xattr_db_connect
  };

NTSTATUS vfs_weka_xattr_db_init( void );
NTSTATUS vfs_weka_xattr_db_init( void )
  /** Insert the module into the VFS stack.
   */
  {
  NTSTATUS rslt;

  rslt = smb_register_vfs( SMB_VFS_INTERFACE_VERSION, /* Interface version.   */
                           weka_xattr_db_mod_name,    /* Logical module name. */
                           &vfs_weka_xattr_db_fns );  /* VFS function set.    */
  return( rslt );
  } /* vfs_weka_xattr_db_init */

/* ========================================================================== */
