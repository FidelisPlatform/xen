#include <xen/errno.h>
#include <xen/gunzip.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>

#define HEAPORDER 3

#define memptr long
static memptr __initdata free_mem_ptr;
static memptr __initdata free_mem_end_ptr;

#define WSIZE           0x80000000U

struct gzip_data {
    unsigned char *window;

    unsigned char *inbuf;
    unsigned int insize;

    /* Index of next byte to be processed in inbuf: */
    unsigned int inptr;

    /* Bytes in output buffer: */
    unsigned int outcnt;

    long bytes_out;

    unsigned long bb;      /* bit buffer */
    unsigned bk;           /* bits in bit buffer */
};

#define OF(args)        args

#define memzero(s, n)   memset((s), 0, (n))

typedef unsigned char   uch;
typedef unsigned short  ush;
typedef unsigned long   ulg;

#define get_byte(gd)      (gd->inptr < gd->insize ? gd->inbuf[gd->inptr++] : fill_inbuf())

/* Diagnostic functions */
#ifdef DEBUG
#  define Assert(cond, msg) do { if (!(cond)) error(msg); } while (0)
#  define Trace(x)      do { fprintf x; } while (0)
#  define Tracev(x)     do { if (verbose) fprintf x ; } while (0)
#  define Tracevv(x)    do { if (verbose > 1) fprintf x ; } while (0)
#  define Tracec(c, x)  do { if (verbose && (c)) fprintf x ; } while (0)
#  define Tracecv(c, x) do { if (verbose > 1 && (c)) fprintf x ; } while (0)
#else
#  define Assert(cond, msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c, x)
#  define Tracecv(c, x)
#endif

static void flush_window(struct gzip_data *gd);

static __init void error(const char *x)
{
    panic("%s\n", x);
}

static __init int fill_inbuf(void)
{
        error("ran out of input data");
        return 0;
}

#include "inflate.c"

static __init void flush_window(struct gzip_data *gd)
{
    /*
     * The window is equal to the output buffer therefore only need to
     * compute the crc.
     */
    unsigned long c = crc;
    unsigned int n;
    unsigned char *in, ch;

    in = gd->window;
    for ( n = 0; n < gd->outcnt; n++ )
    {
        ch = *in++;
        c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
    }
    crc = c;

    gd->bytes_out += (unsigned long)gd->outcnt;
    gd->outcnt = 0;
}

__init int gzip_check(char *image, unsigned long image_len)
{
    unsigned char magic0, magic1;

    if ( image_len < 2 )
        return 0;

    magic0 = (unsigned char)image[0];
    magic1 = (unsigned char)image[1];

    return (magic0 == 0x1f) && ((magic1 == 0x8b) || (magic1 == 0x9e));
}

__init int perform_gunzip(char *output, char *image, unsigned long image_len)
{
    struct gzip_data gd;
    int rc;

    if ( !gzip_check(image, image_len) )
        return 1;

    gd.window = (unsigned char *)output;

    free_mem_ptr = (unsigned long)alloc_xenheap_pages(HEAPORDER, 0);
    if ( !free_mem_ptr )
        return -ENOMEM;

    free_mem_end_ptr = free_mem_ptr + (PAGE_SIZE << HEAPORDER);
    init_allocator();

    gd.inbuf = (unsigned char *)image;
    gd.insize = image_len;
    gd.inptr = 0;
    gd.bytes_out = 0;

    makecrc();

    if ( gunzip(&gd) < 0 )
    {
        rc = -EINVAL;
    }
    else
    {
        rc = 0;
    }

    free_xenheap_pages((void *)free_mem_ptr, HEAPORDER);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
