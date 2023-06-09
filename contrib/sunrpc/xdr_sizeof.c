/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * xdr_sizeof.c
 *
 * Copyright 1990 Sun Microsystems, Inc.
 *
 * General purpose routine to see how much space something will use
 * when serialized using XDR.
 */

#if defined(GF_DARWIN_HOST_OS) || defined(GF_CYGWIN_HOST_OS)

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/types.h>
#include <sys/cdefs.h>

#include <stdlib.h>

/* ARGSUSED */
#ifdef GF_DARWIN_HOST_OS
static bool_t
x_putlong (XDR *xdrs, const int *longp)
{
        xdrs->x_handy += BYTES_PER_XDR_UNIT;
        return TRUE;
}

#else
static bool_t
x_putlong (XDR *xdrs, const long *longp)
{
        xdrs->x_handy += BYTES_PER_XDR_UNIT;
        return TRUE;
}
#endif

/* ARGSUSED */
static bool_t
x_putbytes (XDR *xdrs, const char *bp, u_int len)
{
        xdrs->x_handy += len;
        return TRUE;
}

#ifdef GF_DARWIN_HOST_OS
static u_int
x_getpostn (XDR *xdrs)
{
        return xdrs->x_handy;
}
#else
static u_int
x_getpostn (const XDR *xdrs)
{
        return xdrs->x_handy;
}
#endif

/* ARGSUSED */
static bool_t
x_setpostn (XDR *xdrs, u_int len)
{
        /* This is not allowed */
        return FALSE;
}

static int32_t *
x_inline (XDR *xdrs, u_int len)
{
        if (len == 0)
                return NULL;
        if (xdrs->x_op != XDR_ENCODE)
                return NULL;
        if (len < (u_int) (long int) xdrs->x_base)
        {
                /* x_private was already allocated */
                xdrs->x_handy += len;
                return (int32_t *) xdrs->x_private;
        }
        else
        {
                /* Free the earlier space and allocate new area */
                free (xdrs->x_private);
                if ((xdrs->x_private = (caddr_t) malloc (len)) == NULL)
                {
                        xdrs->x_base = 0;
                        return NULL;
                }
                xdrs->x_base = (void *) (long) len;
                xdrs->x_handy += len;
                return (int32_t *) xdrs->x_private;
        }
}

static int
harmless (void)
{
        /* Always return FALSE/NULL, as the case may be */
        return 0;
}

static void
x_destroy (XDR *xdrs)
{
        xdrs->x_handy = 0;
        xdrs->x_base = 0;
        if (xdrs->x_private)
        {
                free (xdrs->x_private);
                xdrs->x_private = NULL;
        }
        return;
}

unsigned long
xdr_sizeof (xdrproc_t func, void *data)
{
        XDR x;
        struct xdr_ops ops;
        bool_t stat;

#ifdef GF_DARWIN_HOST_OS
        typedef bool_t (*dummyfunc1) (XDR *, int *);
#else
        typedef bool_t (*dummyfunc1) (XDR *, long *);
#endif
        typedef bool_t (*dummyfunc2) (XDR *, caddr_t, u_int);

        ops.x_putlong = x_putlong;
        ops.x_putbytes = x_putbytes;
        ops.x_inline = x_inline;
        ops.x_getpostn = x_getpostn;
        ops.x_setpostn = x_setpostn;
        ops.x_destroy = x_destroy;

        /* the other harmless ones */
        ops.x_getlong = (dummyfunc1) harmless;
        ops.x_getbytes = (dummyfunc2) harmless;

        x.x_op = XDR_ENCODE;
        x.x_ops = &ops;
        x.x_handy = 0;
        x.x_private = (caddr_t) NULL;
        x.x_base = (caddr_t) 0;

        stat = func (&x, data, 0);
        if (x.x_private)
                free (x.x_private);
        return (stat == TRUE ? (unsigned) x.x_handy : 0);
}
#endif /* GF_DARWIN_HOST_OS GF_CYGWIN_HOST_OS */
