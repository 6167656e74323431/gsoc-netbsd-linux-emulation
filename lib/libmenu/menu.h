/*	$NetBSD: menu.h,v 1.8 2000/04/20 12:17:57 blymn Exp $	*/

/*-
 * Copyright (c) 1998-1999 Brett Lymn (blymn@baea.com.au, brett_lymn@yahoo.com.au)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software withough specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */

#ifndef	_MENU_H_
#define	_MENU_H_

#include <curses.h>
#include <eti.h>

/* requests for the menu_driver call */
#define REQ_BASE_NUM      (0x100)
#define REQ_LEFT_ITEM     (0x101)
#define REQ_RIGHT_ITEM    (0x102)
#define REQ_UP_ITEM       (0x103)
#define REQ_DOWN_ITEM     (0x104)
#define REQ_SCR_ULINE     (0x105)
#define REQ_SCR_DLINE     (0x106)
#define REQ_SCR_DPAGE     (0x107)
#define REQ_SCR_UPAGE     (0x108)
#define REQ_FIRST_ITEM    (0x109)
#define REQ_LAST_ITEM     (0x10a)
#define REQ_NEXT_ITEM     (0x10b)
#define REQ_PREV_ITEM     (0x10c)
#define REQ_TOGGLE_ITEM   (0x10d)
#define REQ_CLEAR_PATTERN (0x10e)
#define REQ_BACK_PATTERN  (0x10f)
#define REQ_NEXT_MATCH    (0x110)
#define REQ_PREV_MATCH    (0x111)

#define MAX_COMMAND       (0x111) /* last menu driver request - for application
				     defined commands */

/* Menu options */
typedef unsigned int OPTIONS;

/* and the values they can have */
#define O_ONEVALUE   (0x1)
#define O_SHOWDESC   (0x2)
#define O_ROWMAJOR   (0x4)
#define O_IGNORECASE (0x8)
#define O_SHOWMATCH  (0x10)
#define O_NONCYCLIC  (0x20)
#define O_SELECTABLE (0x40)

typedef struct __menu_str {
        char *string;
        int length;
} MENU_STR;

typedef struct __menu MENU;
typedef struct __item ITEM;

typedef void (*Menu_Hook) (MENU *);

struct __item {
        MENU_STR name;
        MENU_STR description;
        char *userptr;
        int visible;  /* set if item is visible */
        int selected; /* set if item has been selected */
	int row; /* menu row this item is on */
	int col; /* menu column this item is on */
        OPTIONS opts;
        MENU *parent; /* menu this item is bound to */
	int index; /* index number for this item, if attached */
	  /* The following are the item's neighbours - makes menu
	     navigation easier */
	ITEM *left;
	ITEM *right;
	ITEM *up;
	ITEM *down;
};

struct __menu {
        int rows; /* max number of rows to be displayed */
        int cols; /* max number of columns to be displayed */
	int item_rows; /* number of item rows we have */
	int item_cols; /* number of item columns we have */
        int cur_row; /* current cursor row */
        int cur_col; /* current cursor column */
        MENU_STR mark; /* menu mark string */
        MENU_STR unmark; /* menu unmark string */
        OPTIONS opts; /* options for the menu */
        char *pattern; /* the pattern buffer */
	int plen;  /* pattern buffer length */
	int match_len; /* length of pattern matched */
        int posted; /* set if menu is posted */
        attr_t fore; /* menu foreground */
        attr_t back; /* menu background */
        attr_t grey; /* greyed out (nonselectable) menu item */
        int pad;  /* filler char between name and description */
        char *userptr;
	int top_row; /* the row that is at the top of the menu */
	int max_item_width; /* widest item */
	int col_width; /* width of the menu columns - this is not always
			  the same as the widest item */
        int item_count; /* number of items attached */
        ITEM **items; /* items associated with this menu */
        int  cur_item; /* item cursor is currently positioned at */
        int in_init; /* set when processing an init or term function call */
        Menu_Hook menu_init; /* call this when menu is posted */
        Menu_Hook menu_term; /* call this when menu is unposted */
        Menu_Hook item_init; /* call this when menu posted & after
				       current item changes */
        Menu_Hook item_term; /* call this when menu unposted & just
				       before current item changes */
        WINDOW *menu_win; /* the menu window */
        WINDOW *menu_subwin; /* the menu subwindow */
	int we_created;
};


/* Public function prototypes. */
__BEGIN_DECLS
int  menu_driver(MENU *menu, int c);
int scale_menu(MENU *menu, int *rows, int *cols);
int set_top_row(MENU *menu, int row);
int pos_menu_cursor(MENU *menu);
int top_row(MENU *menu);

int  free_menu(MENU *menu);
char menu_back(MENU *menu);
char menu_fore(MENU *menu);
void menu_format(MENU *menu, int *rows, int *cols);
char menu_grey(MENU *menu);
Menu_Hook menu_init(MENU *menu);
char *menu_mark(MENU *menu);
OPTIONS menu_opts(MENU *menu);
int menu_opts_off(MENU *menu, OPTIONS opts);
int menu_opts_on(MENU *menu, OPTIONS opts);
int menu_pad(MENU *menu);
char *menu_pattern(MENU *menu);
WINDOW *menu_sub(MENU *menu);
Menu_Hook menu_term(MENU *menu);
char *menu_unmark (MENU *menu);
char *menu_userptr(MENU *menu);
WINDOW *menu_win(MENU *menu);
MENU *new_menu(ITEM **items);
int post_menu(MENU *menu);
int set_menu_back(MENU *menu, attr_t attr);
int set_menu_fore(MENU *menu, attr_t attr);
int set_menu_format(MENU *menu, int rows, int cols);
int set_menu_grey(MENU *menu, attr_t attr);
int set_menu_init(MENU *menu, Menu_Hook func);
int set_menu_items(MENU *menu, ITEM **items);
int set_menu_mark(MENU *menu, char *mark);
int set_menu_opts(MENU *menu, OPTIONS opts);
int set_menu_pad(MENU *menu, int pad);
int set_menu_pattern(MENU *menu, char *pat);
int set_menu_sub(MENU *menu, WINDOW *subwin);
int set_menu_term(MENU *menu, Menu_Hook func);
int set_menu_unmark(MENU *menu, char *mark);
int set_menu_userptr(MENU *menu, char *userptr);
int  set_menu_win(MENU *menu, WINDOW *win);
int unpost_menu(MENU *menu);

ITEM *current_item(MENU *menu);
int free_item(ITEM *item);
int item_count(MENU *menu);
char *item_description(ITEM *item);
int item_index(ITEM *item);
Menu_Hook item_init(MENU *menu);
char *item_name(ITEM *item);
OPTIONS item_opts(ITEM *item);
int item_opts_off(ITEM *item, OPTIONS opts);
int item_opts_on(ITEM *item, OPTIONS opts);
Menu_Hook item_term(MENU *menu);
char *item_userptr(ITEM *item);
int item_value(ITEM *item);
int item_visible(ITEM *item);
ITEM **menu_items(MENU *menu);
ITEM *new_item(char *name, char *description);
int set_current_item(MENU *menu, ITEM *item);
int set_item_init(MENU *menu, Menu_Hook func);
int set_item_opts(ITEM *menu, OPTIONS opts);
int set_item_term(MENU *menu, Menu_Hook func);
int set_item_userptr(ITEM *item, char *userptr);
int set_item_value(ITEM *item, int flag);

__END_DECLS

#endif /* !_MENU_H_ */
