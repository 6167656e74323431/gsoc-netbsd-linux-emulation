$NetBSD: patch-src_hash.c,v 1.1 2018/02/15 15:21:49 wiz Exp $

Support OpenSSL-1.1.
Based on patch by Hristo Venev in https://github.com/x42/liboauth/issues/9

--- src/hash.c.orig	2013-10-04 13:02:50.000000000 +0000
+++ src/hash.c
@@ -362,6 +362,11 @@ looser:
 #include "oauth.h" // base64 encode fn's.
 #include <openssl/hmac.h>
 
+#if OPENSSL_VERSION_NUMBER < 0x10100000
+#define EVP_MD_CTX_new EVP_MD_CTX_create
+#define EVP_MD_CTX_free EVP_MD_CTX_destroy
+#endif
+
 char *oauth_sign_hmac_sha1 (const char *m, const char *k) {
   return(oauth_sign_hmac_sha1_raw (m, strlen(m), k, strlen(k)));
 }
@@ -386,7 +391,7 @@ char *oauth_sign_rsa_sha1 (const char *m
   unsigned char *sig = NULL;
   unsigned char *passphrase = NULL;
   unsigned int len=0;
-  EVP_MD_CTX md_ctx;
+  EVP_MD_CTX *md_ctx;
 
   EVP_PKEY *pkey;
   BIO *in;
@@ -399,24 +404,31 @@ char *oauth_sign_rsa_sha1 (const char *m
     return xstrdup("liboauth/OpenSSL: can not read private key");
   }
 
+  md_ctx = EVP_MD_CTX_new();
+  if (md_ctx == NULL) {
+    return xstrdup("liboauth/OpenSSL: failed to allocate EVP_MD_CTX");
+  }
+
   len = EVP_PKEY_size(pkey);
   sig = (unsigned char*)xmalloc((len+1)*sizeof(char));
 
-  EVP_SignInit(&md_ctx, EVP_sha1());
-  EVP_SignUpdate(&md_ctx, m, strlen(m));
-  if (EVP_SignFinal (&md_ctx, sig, &len, pkey)) {
+  EVP_SignInit(md_ctx, EVP_sha1());
+  EVP_SignUpdate(md_ctx, m, strlen(m));
+  if (EVP_SignFinal (md_ctx, sig, &len, pkey)) {
     char *tmp;
     sig[len] = '\0';
     tmp = oauth_encode_base64(len,sig);
     OPENSSL_free(sig);
     EVP_PKEY_free(pkey);
+    EVP_MD_CTX_free(md_ctx);
     return tmp;
   }
+  EVP_MD_CTX_free(md_ctx);
   return xstrdup("liboauth/OpenSSL: rsa-sha1 signing failed");
 }
 
 int oauth_verify_rsa_sha1 (const char *m, const char *c, const char *s) {
-  EVP_MD_CTX md_ctx;
+  EVP_MD_CTX *md_ctx;
   EVP_PKEY *pkey;
   BIO *in;
   X509 *cert = NULL;
@@ -437,13 +449,17 @@ int oauth_verify_rsa_sha1 (const char *m
     return -2;
   }
 
+  md_ctx = EVP_MD_CTX_new();
+  if (md_ctx == NULL) {
+    return -2;
+  }
   b64d= (unsigned char*) xmalloc(sizeof(char)*strlen(s));
   slen = oauth_decode_base64(b64d, s);
 
-  EVP_VerifyInit(&md_ctx, EVP_sha1());
-  EVP_VerifyUpdate(&md_ctx, m, strlen(m));
-  err = EVP_VerifyFinal(&md_ctx, b64d, slen, pkey);
-  EVP_MD_CTX_cleanup(&md_ctx);
+  EVP_VerifyInit(md_ctx, EVP_sha1());
+  EVP_VerifyUpdate(md_ctx, m, strlen(m));
+  err = EVP_VerifyFinal(md_ctx, b64d, slen, pkey);
+  EVP_MD_CTX_free(md_ctx);
   EVP_PKEY_free(pkey);
   xfree(b64d);
   return (err);
@@ -455,35 +471,42 @@ int oauth_verify_rsa_sha1 (const char *m
  */
 char *oauth_body_hash_file(char *filename) {
   unsigned char fb[BUFSIZ];
-  EVP_MD_CTX ctx;
+  EVP_MD_CTX *ctx;
   size_t len=0;
   unsigned char *md;
   FILE *F= fopen(filename, "r");
   if (!F) return NULL;
 
-  EVP_MD_CTX_init(&ctx);
-  EVP_DigestInit(&ctx,EVP_sha1());
+  ctx = EVP_MD_CTX_new();
+  if (ctx == NULL) {
+    return xstrdup("liboauth/OpenSSL: failed to allocate EVP_MD_CTX");
+  }
+  EVP_DigestInit(ctx,EVP_sha1());
   while (!feof(F) && (len=fread(fb,sizeof(char),BUFSIZ, F))>0) {
-    EVP_DigestUpdate(&ctx, fb, len);
+    EVP_DigestUpdate(ctx, fb, len);
   }
   fclose(F);
   len=0;
   md=(unsigned char*) xcalloc(EVP_MD_size(EVP_sha1()),sizeof(unsigned char));
-  EVP_DigestFinal(&ctx, md,(unsigned int*) &len);
-  EVP_MD_CTX_cleanup(&ctx);
+  EVP_DigestFinal(ctx, md,(unsigned int*) &len);
+  EVP_MD_CTX_free(ctx);
   return oauth_body_hash_encode(len, md);
 }
 
 char *oauth_body_hash_data(size_t length, const char *data) {
-  EVP_MD_CTX ctx;
+  EVP_MD_CTX *ctx;
   size_t len=0;
   unsigned char *md;
   md=(unsigned char*) xcalloc(EVP_MD_size(EVP_sha1()),sizeof(unsigned char));
-  EVP_MD_CTX_init(&ctx);
-  EVP_DigestInit(&ctx,EVP_sha1());
-  EVP_DigestUpdate(&ctx, data, length);
-  EVP_DigestFinal(&ctx, md,(unsigned int*) &len);
-  EVP_MD_CTX_cleanup(&ctx);
+  ctx = EVP_MD_CTX_new();
+  if (ctx == NULL) {
+    return xstrdup("liboauth/OpenSSL: failed to allocate EVP_MD_CTX");
+  }
+  EVP_MD_CTX_init(ctx);
+  EVP_DigestInit(ctx,EVP_sha1());
+  EVP_DigestUpdate(ctx, data, length);
+  EVP_DigestFinal(ctx, md,(unsigned int*) &len);
+  EVP_MD_CTX_free(ctx);
   return oauth_body_hash_encode(len, md);
 }
 
