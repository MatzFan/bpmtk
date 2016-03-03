/*
	pcre for Basic Process Manipulation Tool Kit (BPMTK)
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcomings, or todo's ;-)
	
	History:
	2008/02/24: start
*/

#ifndef _PCRE_H_
#define _PCRE_H_

#define PCRE_ERROR_NOMATCH         (-1)

struct real_pcre;                 /* declaration; the definition is private  */

typedef struct real_pcre pcre;

typedef struct pcre_extra {
  unsigned long int flags;        /* Bits for which fields are set */
  void *study_data;               /* Opaque data from pcre_study() */
  unsigned long int match_limit;  /* Maximum number of calls to match() */
  void *callout_data;             /* Data passed back in callouts */
  const unsigned char *tables;    /* Pointer to character tables */
  unsigned long int match_limit_recursion; /* Max recursive calls to match() */
} pcre_extra;

typedef pcre *(*PCRELIB_compile)(const char *, int, const char **, int *, const unsigned char *);

typedef int (*PCRELIB_exec)(const pcre *, const pcre_extra *, const char *, int, int, int, int *, int);

typedef void (*PCRELIB_free)(void *);

#endif