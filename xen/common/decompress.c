#include <xen/init.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <xen/decompress.h>

static void __init cf_check error(const char *msg)
{
    printk("%s\n", msg);
}

int __init decompress(void *inbuf, unsigned int len, void *outbuf)
{
#if 0 /* Not needed here yet. */
    if ( len >= 2 &&
         (!memcmp(inbuf, "\037\213", 2) || !memcmp(inbuf, "\037\236", 2)) )
        return gunzip(inbuf, len, NULL, NULL, outbuf, NULL, error);
#endif

    if ( len >= 3 && !memcmp(inbuf, "\x42\x5a\x68", 3) )
        return bunzip2(inbuf, len, NULL, NULL, outbuf, NULL, error);

    if ( len >= 6 && !memcmp(inbuf, "\375" "7zXZ", 6) )
        return unxz(inbuf, len, NULL, NULL, outbuf, NULL, error);

    if ( len >= 2 && !memcmp(inbuf, "\135\000", 2) )
        return unlzma(inbuf, len, NULL, NULL, outbuf, NULL, error);

    if ( len >= 5 && !memcmp(inbuf, "\x89" "LZO", 5) )
        return unlzo(inbuf, len, NULL, NULL, outbuf, NULL, error);

    if ( len >= 2 && !memcmp(inbuf, "\x02\x21", 2) )
	return unlz4(inbuf, len, NULL, NULL, outbuf, NULL, error);

    if ( len >= 4 && !memcmp(inbuf, "\x28\xb5\x2f\xfd", 4) )
	return unzstd(inbuf, len, NULL, NULL, outbuf, NULL, error);

    return 1;
}
