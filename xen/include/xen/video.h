/*
 *  video.h
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef _XEN_VIDEO_H
#define _XEN_VIDEO_H

#include <public/xen.h>

#ifdef CONFIG_VIDEO
void video_init(void);
extern void (*video_puts)(const char *s, size_t nr);
void video_endboot(void);
#else
#define video_init()    ((void)0)
static inline void video_puts(const char *str, size_t nr) {}
#define video_endboot() ((void)0)
#endif

#endif /* _XEN_VIDEO_H */
