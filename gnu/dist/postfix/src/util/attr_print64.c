/*	$NetBSD: attr_print64.c,v 1.1.1.3 2004/05/31 00:24:55 heas Exp $	*/

/*++
/* NAME
/*	attr_print64 3
/* SUMMARY
/*	send attributes over byte stream
/* SYNOPSIS
/*	#include <attr.h>
/*
/*	int	attr_print64(fp, flags, type, name, ..., ATTR_TYPE_END)
/*	VSTREAM	fp;
/*	int	flags;
/*	int	type;
/*	char	*name;
/*
/*	int	attr_vprint64(fp, flags, ap)
/*	VSTREAM	fp;
/*	int	flags;
/*	va_list	ap;
/* DESCRIPTION
/*	attr_print64() takes zero or more (name, value) simple attributes
/*	and converts its input to a byte stream that can be recovered with
/*	attr_scan64(). The stream is not flushed.
/*
/*	attr_vprint64() provides an alternate interface that is convenient
/*	for calling from within variadoc functions.
/*
/*	Attributes are sent in the requested order as specified with the
/*	attr_print64() argument list. This routine satisfies the formatting
/*	rules as outlined in attr_scan64(3).
/*
/*	Arguments:
/* .IP fp
/*	Stream to write the result to.
/* .IP flags
/*	The bit-wise OR of zero or more of the following.
/* .RS
/* .IP ATTR_FLAG_MORE
/*	After sending the requested attributes, leave the output stream in
/*	a state that is usable for more attribute sending operations on
/*	the same output attribute list.
/*	By default, attr_print64() automatically appends an attribute list
/*	terminator when it has sent the last requested attribute.
/* .RE
/* .IP type
/*	The type determines the arguments that follow.
/* .RS
/* .IP "ATTR_TYPE_NUM (char *, int)"
/*	This argument is followed by an attribute name and an integer.
/* .IP "ATTR_TYPE_NUM (char *, long)"
/*	This argument is followed by an attribute name and a long integer.
/* .IP "ATTR_TYPE_STR (char *, char *)"
/*	This argument is followed by an attribute name and a null-terminated
/*	string.
/* .IP "ATTR_TYPE_HASH (HTABLE *)"
/* .IP "ATTR_TYPE_NAMEVAL (NVTABLE *)"
/*	The content of the table is sent as a sequence of string-valued
/*	attributes with names equal to the table lookup keys.
/* .IP ATTR_TYPE_END
/*	This terminates the attribute list.
/* .RE
/* DIAGNOSTICS
/*	The result value is 0 in case of success, VSTREAM_EOF in case
/*	of trouble.
/*
/*	Panic: interface violation. All system call errors are fatal.
/* SEE ALSO
/*	attr_scan64(3) recover attributes from byte stream
/* LICENSE
/* .ad
/* .fi
/*	The Secure Mailer license must be distributed with this software.
/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*--*/

/* System library. */

#include <sys_defs.h>
#include <stdarg.h>
#include <string.h>

/* Utility library. */

#include <msg.h>
#include <mymalloc.h>
#include <vstream.h>
#include <htable.h>
#include <base64_code.h>
#include <attr.h>

#define STR(x)	vstring_str(x)
#define LEN(x)	VSTRING_LEN(x)

/* attr_print64_str - encode and send attribute information */

static void attr_print64_str(VSTREAM *fp, const char *str, int len)
{
    static VSTRING *base64_buf;

    if (base64_buf == 0)
	base64_buf = vstring_alloc(10);

    base64_encode(base64_buf, str, len);
    vstream_fputs(STR(base64_buf), fp);
}

static void attr_print64_num(VSTREAM *fp, unsigned num)
{
    static VSTRING *plain;

    if (plain == 0)
	plain = vstring_alloc(10);

    vstring_sprintf(plain, "%u", num);
    attr_print64_str(fp, STR(plain), LEN(plain));
}

static void attr_print64_long_num(VSTREAM *fp, unsigned long long_num)
{
    static VSTRING *plain;

    if (plain == 0)
	plain = vstring_alloc(10);

    vstring_sprintf(plain, "%lu", long_num);
    attr_print64_str(fp, STR(plain), LEN(plain));
}

/* attr_vprint64 - send attribute list to stream */

int     attr_vprint64(VSTREAM *fp, int flags, va_list ap)
{
    const char *myname = "attr_print64";
    int     attr_type;
    char   *attr_name;
    unsigned int_val;
    unsigned long long_val;
    char   *str_val;
    HTABLE_INFO **ht_info_list;
    HTABLE_INFO **ht;

    /*
     * Sanity check.
     */
    if (flags & ~ATTR_FLAG_ALL)
	msg_panic("%s: bad flags: 0x%x", myname, flags);

    /*
     * Iterate over all (type, name, value) triples, and produce output on
     * the fly.
     */
    while ((attr_type = va_arg(ap, int)) != ATTR_TYPE_END) {
	switch (attr_type) {
	case ATTR_TYPE_NUM:
	    attr_name = va_arg(ap, char *);
	    attr_print64_str(fp, attr_name, strlen(attr_name));
	    int_val = va_arg(ap, int);
	    VSTREAM_PUTC(':', fp);
	    attr_print64_num(fp, (unsigned) int_val);
	    VSTREAM_PUTC('\n', fp);
	    if (msg_verbose)
		msg_info("send attr %s = %u", attr_name, int_val);
	    break;
	case ATTR_TYPE_LONG:
	    attr_name = va_arg(ap, char *);
	    attr_print64_str(fp, attr_name, strlen(attr_name));
	    long_val = va_arg(ap, long);
	    VSTREAM_PUTC(':', fp);
	    attr_print64_long_num(fp, (unsigned long) long_val);
	    VSTREAM_PUTC('\n', fp);
	    if (msg_verbose)
		msg_info("send attr %s = %lu", attr_name, long_val);
	    break;
	case ATTR_TYPE_STR:
	    attr_name = va_arg(ap, char *);
	    attr_print64_str(fp, attr_name, strlen(attr_name));
	    str_val = va_arg(ap, char *);
	    VSTREAM_PUTC(':', fp);
	    attr_print64_str(fp, str_val, strlen(str_val));
	    VSTREAM_PUTC('\n', fp);
	    if (msg_verbose)
		msg_info("send attr %s = %s", attr_name, str_val);
	    break;
	case ATTR_TYPE_HASH:
	    ht_info_list = htable_list(va_arg(ap, HTABLE *));
	    for (ht = ht_info_list; *ht; ht++) {
		attr_print64_str(fp, ht[0]->key, strlen(ht[0]->key));
		VSTREAM_PUTC(':', fp);
		attr_print64_str(fp, ht[0]->value, strlen(ht[0]->value));
		VSTREAM_PUTC('\n', fp);
		if (msg_verbose)
		    msg_info("send attr name %s value %s",
			     ht[0]->key, ht[0]->value);
	    }
	    myfree((char *) ht_info_list);
	    break;
	default:
	    msg_panic("%s: unknown type code: %d", myname, attr_type);
	}
    }
    if ((flags & ATTR_FLAG_MORE) == 0)
	VSTREAM_PUTC('\n', fp);
    return (vstream_ferror(fp));
}

int     attr_print64(VSTREAM *fp, int flags,...)
{
    va_list ap;
    int     ret;

    va_start(ap, flags);
    ret = attr_vprint64(fp, flags, ap);
    va_end(ap);
    return (ret);
}

#ifdef TEST

 /*
  * Proof of concept test program.  Mirror image of the attr_scan64 test
  * program.
  */
#include <msg_vstream.h>

int     main(int unused_argc, char **argv)
{
    HTABLE *table = htable_create(1);

    msg_vstream_init(argv[0], VSTREAM_ERR);
    msg_verbose = 1;
    htable_enter(table, "foo-name", mystrdup("foo-value"));
    htable_enter(table, "bar-name", mystrdup("bar-value"));
    attr_print64(VSTREAM_OUT, ATTR_FLAG_NONE,
		 ATTR_TYPE_NUM, ATTR_NAME_NUM, 4711,
		 ATTR_TYPE_LONG, ATTR_NAME_LONG, 1234,
		 ATTR_TYPE_STR, ATTR_NAME_STR, "whoopee",
		 ATTR_TYPE_HASH, table,
		 ATTR_TYPE_END);
    attr_print64(VSTREAM_OUT, ATTR_FLAG_NONE,
		 ATTR_TYPE_NUM, ATTR_NAME_NUM, 4711,
		 ATTR_TYPE_LONG, ATTR_NAME_LONG, 1234,
		 ATTR_TYPE_STR, ATTR_NAME_STR, "whoopee",
		 ATTR_TYPE_END);
    if (vstream_fflush(VSTREAM_OUT) != 0)
	msg_fatal("write error: %m");

    htable_free(table, myfree);
    return (0);
}

#endif
