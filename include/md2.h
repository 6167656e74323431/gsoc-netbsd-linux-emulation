/*	$NetBSD: md2.h,v 1.3 2005/09/24 21:30:38 elad Exp $	*/

#ifndef _MD2_H_
#define _MD2_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#define	MD2_DIGEST_LENGTH		16
#define	MD2_DIGEST_STRING_LENGTH	33

/* MD2 context. */
typedef struct MD2Context {
	u_int32_t i;
	unsigned char C[16];		/* checksum */
	unsigned char X[48];		/* input buffer */
} MD2_CTX;

__BEGIN_DECLS
void	MD2Init(MD2_CTX *);
void	MD2Update(MD2_CTX *, const unsigned char *, unsigned int);
void	MD2Final(unsigned char[16], MD2_CTX *);
char	*MD2End(MD2_CTX *, char *);
char	*MD2File(const char *, char *);
char	*MD2Data(const unsigned char *, unsigned int, char *);
__END_DECLS

#endif /* _MD2_H_ */
