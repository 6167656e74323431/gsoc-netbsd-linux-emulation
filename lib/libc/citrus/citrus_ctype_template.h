/*	$NetBSD: citrus_ctype_template.h,v 1.3 2002/03/18 10:01:12 yamt Exp $	*/

/*-
 * Copyright (c)2002 Citrus Project,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*-
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/*
 * CAUTION: THIS IS NOT STANDALONE FILE
 *
 * function templates of ctype encoding handler for each encodings.
 *
 * you need to define the macros below:
 *
 *   _FUNCNAME(method) :
 *   	It should convine the real function name for the method.
 *      e.g. _FUNCNAME(mbrtowc) should be expanded to
 *             _EUC_ctype_mbrtowc
 *           for EUC locale.
 *
 *   _TO_INTERNAL_STATE(ei, method) :
 *     It should be expanded to the pointer of the method-internal state
 *     structures.
 *     e.g. _TO_INTERNAL_STATE(ei, mbrtowc) might be expanded to
 *             (ei)->states.s_mbrtowc
 *     This structure may use if the function is called as
 *           mbrtowc(&wc, s, n, NULL);
 *     Such individual structures are needed by:
 *           mblen
 *           mbrlen
 *           mbrtowc
 *           mbtowc
 *           mbsrtowcs
 *           wcrtomb
 *           wcsrtombs
 *           wcstombs
 *           wctomb
 *     These need to be keeped in the encoding information structure,
 *     pointed by "ei".
 *
 *   _ENCODING_INFO :
 *     It should be expanded to the name of the encoding information structure.
 *     e.g. For EUC encoding, this macro is expanded to _EUCInfo.
 *     Encoding information structure need to contain the common informations
 *     for the codeset.
 *
 *   _ENCODING_STATE :
 *     It should be expanded to the name of the encoding state structure.
 *     e.g. For EUC encoding, this macro is expanded to _EUCState.
 *     Encoding state structure need to contain the context-dependent states,
 *     which are "unpacked-form" of mbstate_t type and keeped during sequent
 *     calls of mb/wc functions,
 *
 *   _ENCODING_IS_STATE_DEPENDENT :
 *     If the encoding is state dependent, this should be expanded to
 *     non-zero integral value.  Otherwise, 0.
 *
 */


/* prototypes */

__BEGIN_DECLS
static void _FUNCNAME(init_state)(_ENCODING_INFO * __restrict,
				  _ENCODING_STATE * __restrict);
static void _FUNCNAME(pack_state)(_ENCODING_INFO * __restrict,
				  void * __restrict,
				  const _ENCODING_STATE * __restrict);
static void _FUNCNAME(unpack_state)(_ENCODING_INFO * __restrict,
				    _ENCODING_STATE * __restrict,
				    const void * __restrict);


/*
 * standard form of mbrtowc_priv.
 *
 * note (differences from real mbrtowc):
 *   - 3rd parameter is not "const char *s" but "const char **s".
 *     after the call of the function, *s will point the first byte of
 *     the next character.
 *   - additional 4th parameter is the size of src buffer.
 *   - 5th parameter is unpacked encoding-dependent state structure.
 *   - additional 6th parameter is the storage to be stored
 *     the return value in the real mbrtowc context.
 *   - return value means "errno" in the real mbrtowc context.
 */

static int _FUNCNAME(mbrtowc_priv)(_ENCODING_INFO * __restrict,
				   wchar_t * __restrict,
				   const char ** __restrict,
				   size_t, _ENCODING_STATE * __restrict,
				   size_t * __restrict);

/*
 * standard form of wcrtomb_priv.
 *
 * note (differences from real wcrtomb):
 *   - additional 3th parameter is the size of src buffer.
 *   - 5th parameter is unpacked encoding-dependent state structure.
 *   - additional 6th parameter is the storage to be stored
 *     the return value in the real mbrtowc context.
 *   - return value means "errno" in the real wcrtomb context.
 */

static int _FUNCNAME(wcrtomb_priv)(_ENCODING_INFO * __restrict,
				   char * __restrict, size_t, wchar_t,
				   _ENCODING_STATE * __restrict,
				   size_t * __restrict);
__END_DECLS


/*
 * templates
 */

/* internal routines */

static __inline int
_FUNCNAME(mbtowc_priv)(_ENCODING_INFO * __restrict ei,
		       wchar_t * __restrict pwc,  const char * __restrict s,
		       size_t n, _ENCODING_STATE * __restrict psenc,
		       int * __restrict nresult)
{
	_ENCODING_STATE state;
	size_t nr;
	int err = 0;

	_DIAGASSERT(ei != NULL);
	_DIAGASSERT(psenc != NULL);

	if (s == NULL) {
		return (int)_ENCODING_IS_STATE_DEPENDENT;
	}

	state = *psenc;
	err = _FUNCNAME(mbrtowc_priv)(ei, pwc, &s, n, psenc, &nr);
	if (err) {
		*nresult = -1;
		return (err);
	}
	if (nr==(size_t)-2) {
		*psenc = state;
		*nresult = -1;
		return (EILSEQ);
	}

	*nresult = (int)nr;

	return (0);
}

static int
_FUNCNAME(mbsrtowcs_priv)(_ENCODING_INFO * __restrict ei,
			  wchar_t * __restrict pwcs,
			  const char ** __restrict s,
			  size_t n, _ENCODING_STATE * __restrict psenc,
			  size_t * __restrict nresult)
{
	int err, cnt;
	size_t siz;
	const char *s0;

	_DIAGASSERT(nresult != 0);
	_DIAGASSERT(ei != NULL);
	_DIAGASSERT(psenc != NULL);

	if (s == NULL || *s == NULL || n==0) {
		*nresult = (size_t)-1;
		return EILSEQ;
	}

	if (!pwcs)
		n = 1;

	cnt = 0;
	s0 = *s; /* to keep *s unchanged for now, use copy instead. */
	while (n > 0) {
		err = _FUNCNAME(mbrtowc_priv)(ei, pwcs, &s0, MB_CUR_MAX,
					      psenc, &siz);
		if (siz == (size_t)-2)
			err = EILSEQ;
		if (err) {
			cnt = -1;
			goto bye;
		}
		switch (siz) {
		case 0:
			if (pwcs) {
				_FUNCNAME(init_state)(ei, psenc);
			}
			s0 = 0;
			goto bye;
		default:
			if (pwcs) {
				pwcs++;
				n--;
			}
			cnt++;
			break;
		}
	}
bye:
	if (pwcs)
		*s = s0;

	*nresult = (size_t)cnt;

	return err;
}


static int
_FUNCNAME(wcsrtombs_priv)(_ENCODING_INFO * __restrict ei, char * __restrict s,
			  const wchar_t ** __restrict pwcs,
			  size_t n, _ENCODING_STATE * __restrict psenc,
			  size_t * __restrict nresult)
{
	int cnt = 0, err;
	char buf[MB_LEN_MAX];
	size_t siz;
	const wchar_t* pwcs0;

	pwcs0 = *pwcs;
	while (1/*CONSTCOND*/) {
		err = _FUNCNAME(wcrtomb_priv)(ei, buf, sizeof(buf),
					      *pwcs0, psenc, &siz);
		if (siz == (size_t)-1) {
			*nresult = siz;
			return (err);
		}

		if (s) {
			if (n - cnt < siz)
				break;
			memcpy(s, buf, siz);
		}
		if (!*pwcs0) {
			if (s) {
				_FUNCNAME(init_state)(ei, psenc);
			}
			pwcs0 = 0;
			break;
		}
		if (s)
			s += siz;
		cnt += siz;
		pwcs0++;
	}
	if (s)
		*pwcs = pwcs0;

	*nresult = (size_t)cnt;
	return (0);
}


/* ----------------------------------------------------------------------
 * templates for public functions
 */

#define _RESTART_BEGIN(_func_, _cei_, _pspriv_, _pse_)			\
do {									\
	_ENCODING_STATE _state;						\
	do {								\
		if (_pspriv_ == NULL) {					\
			_pse_ = &_CEI_TO_STATE(_cei_, _func_);		\
		} else {						\
			_pse_ = &_state;				\
			_FUNCNAME(unpack_state)(_CEI_TO_EI(_cei_),	\
						_pse_, _pspriv_);	\
		}							\
	} while (/*CONSTCOND*/0)

#define _RESTART_END(_func_, _cei_, _pspriv_, _pse_)			\
	if (_pspriv_ != NULL) {						\
		_FUNCNAME(pack_state)(_CEI_TO_EI(_cei_), _pspriv_,	\
				      _pse_);				\
	}								\
} while (/*CONSTCOND*/0)

int
_FUNCNAME(ctype_getops)(_citrus_ctype_ops_rec_t *ops, size_t lenops,
			u_int32_t expected_version)
{
	if (expected_version<_CITRUS_CTYPE_ABI_VERSION || lenops<sizeof(*ops))
		return (EINVAL);

	memcpy(ops, &_FUNCNAME(ctype_ops), sizeof(_FUNCNAME(ctype_ops)));

	return (0);
}

static int
_FUNCNAME(ctype_init)(void ** __restrict cl,
		      void * __restrict var, size_t lenvar, size_t lenps)
{
	_CTYPE_INFO *cei;

	_DIAGASSERT(cl != NULL);

	/* sanity check to avoid overruns */
	if (sizeof(_ENCODING_STATE) > lenps)
		return (EINVAL);

	cei = calloc(1, sizeof(_CTYPE_INFO));
	if (cei == NULL)
		return (ENOMEM);

	*cl = (void *)cei;

	return _FUNCNAME(stdencoding_init)(_CEI_TO_EI(cei), var, lenvar);
}

static void
_FUNCNAME(ctype_uninit)(void *cl)
{
	if (cl) {
		_FUNCNAME(stdencoding_uninit)(_CEI_TO_EI(_TO_CEI(cl)));
		free(cl);
	}
}

static unsigned
/*ARGSUSED*/
_FUNCNAME(ctype_get_mb_cur_max)(void *cl)
{
	return _ENCODING_MB_CUR_MAX(cl);
}

static int
_FUNCNAME(ctype_mblen)(void * __restrict cl,
		       const char * __restrict s, size_t n,
		       int * __restrict nresult)
{

	_DIAGASSERT(cl != NULL);

	return _FUNCNAME(mbtowc_priv)(_TO_EI(cl), NULL, s, n,
				      &_CEI_TO_STATE(_TO_CEI(cl), mblen),
				      nresult);
}

static int
_FUNCNAME(ctype_mbrlen)(void * __restrict cl, const char * __restrict s,
			size_t n, void * __restrict pspriv,
			size_t * __restrict nresult)
{
	_ENCODING_STATE *psenc;
	int err = 0;

	_DIAGASSERT(cl != NULL);

	_RESTART_BEGIN(mbrlen, _TO_CEI(cl), pspriv, psenc);
	if (s == NULL) {
		_FUNCNAME(init_state)(_TO_EI(cl), psenc);
		*nresult = 0;
	} else {
		err = _FUNCNAME(mbrtowc_priv)(
			cl, NULL, &s, n, (void *)psenc, nresult);
	}
	_RESTART_END(mbrlen, _TO_CEI(cl), pspriv, psenc);

	return (err);
}

static int
_FUNCNAME(ctype_mbrtowc)(void * __restrict cl, wchar_t * __restrict pwc,
			 const char * __restrict s, size_t n,
			 void * __restrict pspriv, size_t * __restrict nresult)
{
	_ENCODING_STATE *psenc;
	int err = 0;

	_DIAGASSERT(cl != NULL);

	_RESTART_BEGIN(mbrtowc, _TO_CEI(cl), pspriv, psenc);
	if (s == NULL) {
		_FUNCNAME(init_state)(_CEI_TO_EI(_TO_CEI(cl)), psenc);
		*nresult = 0;
	} else {
		err = _FUNCNAME(mbrtowc_priv)(
			cl, pwc, &s, n, (void *)psenc, nresult);
	}
	_RESTART_END(mbrtowc, _TO_CEI(cl), pspriv, psenc);

	return (err);
}

static int
/*ARGSUSED*/
_FUNCNAME(ctype_mbsinit)(void * __restrict cl, const void * __restrict pspriv,
			 int * __restrict nresult)
{
	_ENCODING_STATE state;

	if (pspriv == NULL) {
		*nresult = 1;
		return (0);
	}

	_FUNCNAME(unpack_state)(_CEI_TO_EI(_TO_CEI(cl)), &state, pspriv);

	*nresult = (state.chlen == 0); /* XXX: FIXME */

	return (0);
}

static int
_FUNCNAME(ctype_mbsrtowcs)(void * __restrict cl, wchar_t * __restrict pwcs,
			   const char ** __restrict s, size_t n,
			   void * __restrict pspriv,
			   size_t * __restrict nresult)
{
	_ENCODING_STATE *psenc;
	int err = 0;

	_DIAGASSERT(cl != NULL);

	_RESTART_BEGIN(mbsrtowcs, _TO_CEI(cl), pspriv, psenc);
	err = _FUNCNAME(mbsrtowcs_priv)(cl, pwcs, s, n, psenc, nresult);
	_RESTART_END(mbsrtowcs, _TO_CEI(cl), pspriv, psenc);

	return (err);
}

static int
_FUNCNAME(ctype_mbstowcs)(void * __restrict cl, wchar_t * __restrict pwcs,
			  const char * __restrict s, size_t n,
			  size_t * __restrict nresult)
{
	int err;
	_ENCODING_STATE state;

	_DIAGASSERT(cl != NULL);

	_FUNCNAME(init_state)(_CEI_TO_EI(_TO_CEI(cl)), &state);
	err = _FUNCNAME(mbsrtowcs_priv)(cl, pwcs, &s, n, &state, nresult);
	if (*nresult == (size_t)-2) {
		err = EILSEQ;
		*nresult = (size_t)-1;
	}

	return (err);
}

static int
_FUNCNAME(ctype_mbtowc)(void * __restrict cl, wchar_t * __restrict pwc,
			const char * __restrict s, size_t n,
			int * __restrict nresult)
{

	_DIAGASSERT(cl != NULL);

	return _FUNCNAME(mbtowc_priv)(cl, pwc, s, n,
				      &_CEI_TO_STATE(_TO_CEI(cl), mbtowc),
				      nresult);
}

static int
_FUNCNAME(ctype_wcrtomb)(void * __restrict cl, char * __restrict s, wchar_t wc,
			 void * __restrict pspriv, size_t * __restrict nresult)
{
	_ENCODING_STATE *psenc;
	int err = 0;

	_DIAGASSERT(cl != NULL);

	_RESTART_BEGIN(wcrtomb, _TO_CEI(cl), pspriv, psenc);
	err = _FUNCNAME(wcrtomb_priv)(_CEI_TO_EI(_TO_CEI(cl)), s, MB_CUR_MAX,
				      wc, psenc, nresult);
	_RESTART_END(wcrtomb, _TO_CEI(cl), pspriv, psenc);

	return err;
}

static int
/*ARGSUSED*/
_FUNCNAME(ctype_wcsrtombs)(void * __restrict cl, char * __restrict s,
			   const wchar_t ** __restrict pwcs, size_t n,
			   void * __restrict pspriv,
			   size_t * __restrict nresult)
{
	_ENCODING_STATE *psenc;
	int err = 0;

	_DIAGASSERT(cl != NULL);

	_RESTART_BEGIN(wcsrtombs, _TO_CEI(cl), pspriv, psenc);
	err = _FUNCNAME(wcsrtombs_priv)(cl, s, pwcs, n, psenc, nresult);
	_RESTART_END(wcsrtombs, _TO_CEI(cl), pspriv, psenc);

	return err;
}

static int
/*ARGSUSED*/
_FUNCNAME(ctype_wcstombs)(void * __restrict cl, char * __restrict s,
			  const wchar_t * __restrict pwcs, size_t n,
			  size_t * __restrict nresult)
{
	int err;

	_DIAGASSERT(cl != NULL);

	/* XXX: FIXME */
	err = _FUNCNAME(wcsrtombs_priv)(cl, s, &pwcs, n,
					&_CEI_TO_STATE(_TO_CEI(cl), wcstombs),
					nresult);

	return err;
}

static int
_FUNCNAME(ctype_wctomb)(void * __restrict cl, char * __restrict s, wchar_t wc,
			int * __restrict nresult)
{
	size_t nr;
	int err = 0;
	char s0[MB_LEN_MAX];

	_DIAGASSERT(cl != NULL);

	if (s==NULL)
		s = s0;

	err = _FUNCNAME(wcrtomb_priv)(cl, s, MB_CUR_MAX, wc,
				      &_CEI_TO_STATE(_TO_CEI(cl), wctomb),
				      &nr);
	*nresult = (int)nr;

	return 0;
}
