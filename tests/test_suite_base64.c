#if !defined(POLARSSL_CONFIG_FILE)
#include <polarssl/config.h>
#else
#include POLARSSL_CONFIG_FILE
#endif

#ifdef POLARSSL_BASE64_C

#include <polarssl/base64.h>
#endif /* POLARSSL_BASE64_C */


#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#include "polarssl/memory.h"
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

/**
 * This function just returns data from rand().
 * Although predictable and often similar on multiple
 * runs, this does not result in identical random on
 * each run. So do not use this if the results of a
 * test depend on the random data that is generated.
 *
 * rng_state shall be NULL.
 */
static int rnd_std_rand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/**
 * This function only returns zeros
 *
 * rng_state shall be NULL.
 */
static int rnd_zero_rand( void *rng_state, unsigned char *output, size_t len )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    memset( output, 0, len );

    return( 0 );
}

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

/**
 * This function returns random based on a buffer it receives.
 *
 * rng_state shall be a pointer to a rnd_buf_info structure.
 * 
 * The number of bytes released from the buffer on each call to
 * the random function is specified by per_call. (Can be between
 * 1 and 4)
 *
 * After the buffer is empty it will return rand();
 */
static int rnd_buffer_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_buf_info *info = (rnd_buf_info *) rng_state;
    size_t use_len;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    use_len = len;
    if( len > info->length )
        use_len = info->length;

    if( use_len )
    {
        memcpy( output, info->buf, use_len );
        info->buf += use_len;
        info->length -= use_len;
    }

    if( len - use_len > 0 )
        return( rnd_std_rand( NULL, output + use_len, len - use_len ) );

    return( 0 );
}

/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

/**
 * This function returns random based on a pseudo random function.
 * This means the results should be identical on all systems.
 * Pseudo random is based on the XTEA encryption algorithm to
 * generate pseudorandom.
 *
 * rng_state shall be a pointer to a rnd_pseudo_info structure.
 */
static int rnd_pseudo_rand( void *rng_state, unsigned char *output, size_t len )
{
    rnd_pseudo_info *info = (rnd_pseudo_info *) rng_state;
    uint32_t i, *k, sum, delta=0x9E3779B9;
    unsigned char result[4], *out = output;

    if( rng_state == NULL )
        return( rnd_std_rand( NULL, output, len ) );

    k = info->key;

    while( len > 0 )
    {
        size_t use_len = ( len > 4 ) ? 4 : len;
        sum = 0;

        for( i = 0; i < 32; i++ )
        {
            info->v0 += (((info->v1 << 4) ^ (info->v1 >> 5)) + info->v1) ^ (sum + k[sum & 3]);
            sum += delta;
            info->v1 += (((info->v0 << 4) ^ (info->v0 >> 5)) + info->v0) ^ (sum + k[(sum>>11) & 3]);
        }

        PUT_UINT32_BE( info->v0, result, 0 );
        memcpy( out, result, use_len );
        len -= use_len;
        out += 4;
    }

    return( 0 );
}


#include <stdio.h>
#include <string.h>

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#define polarssl_printf     printf
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

static int test_errors = 0;

#ifdef POLARSSL_BASE64_C

#define TEST_SUITE_ACTIVE

static int test_assert( int correct, const char *test )
{
    if( correct )
        return( 0 );

    test_errors++;
    if( test_errors == 1 )
        printf( "FAILED\n" );
    printf( "  %s\n", test );

    return( 1 );
}

#define TEST_ASSERT( TEST )                         \
        do { test_assert( (TEST) ? 1 : 0, #TEST );  \
             if( test_errors) return;               \
        } while (0)

int verify_string( char **str )
{
    if( (*str)[0] != '"' ||
        (*str)[strlen( *str ) - 1] != '"' )
    {
        printf( "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    (*str)++;
    (*str)[strlen( *str ) - 1] = '\0';

    return( 0 );
}

int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && str[i] == 'x' )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    if( strcmp( str, "POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL" ) == 0 )
    {
        *value = ( POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL );
        return( 0 );
    }
    if( strcmp( str, "POLARSSL_ERR_BASE64_INVALID_CHARACTER" ) == 0 )
    {
        *value = ( POLARSSL_ERR_BASE64_INVALID_CHARACTER );
        return( 0 );
    }


    printf( "Expected integer for parameter and got: %s\n", str );
    return( -1 );
}

void test_suite_base64_encode( char *src_string, char *dst_string, int dst_buf_size,
                    int result )
{
    unsigned char src_str[1000];
    unsigned char dst_str[1000];
    size_t len = dst_buf_size;

    memset(src_str, 0x00, 1000);
    memset(dst_str, 0x00, 1000);

    strncpy( (char *) src_str, src_string, sizeof(src_str) - 1 );
    TEST_ASSERT( base64_encode( dst_str, &len, src_str, strlen( (char *) src_str ) ) == result );
    if( result == 0 )
    {
        TEST_ASSERT( strcmp( (char *) dst_str, dst_string ) == 0 );
    }
}

void test_suite_base64_decode( char *src_string, char *dst_string, int result )
{
    unsigned char src_str[1000];
    unsigned char dst_str[1000];
    size_t len = 1000;
    int res; 

    memset(src_str, 0x00, 1000);
    memset(dst_str, 0x00, 1000);

    strncpy( (char *) src_str, src_string, sizeof(src_str) - 1 );
    res = base64_decode( dst_str, &len, src_str, strlen( (char *) src_str ) );
    TEST_ASSERT( res == result );
    if( result == 0 )
    {
        TEST_ASSERT( strcmp( (char *) dst_str, dst_string ) == 0 );
    }
}

#ifdef POLARSSL_SELF_TEST
void test_suite_base64_selftest()
{
    TEST_ASSERT( base64_self_test( 0 ) == 0 );
}
#endif /* POLARSSL_SELF_TEST */


#endif /* POLARSSL_BASE64_C */


int dep_check( char *str )
{
    if( str == NULL )
        return( 1 );

    if( strcmp( str, "POLARSSL_SELF_TEST" ) == 0 )
    {
#if defined(POLARSSL_SELF_TEST)
        return( 0 );
#else
        return( 1 );
#endif
    }


    return( 1 );
}

int dispatch_test(int cnt, char *params[50])
{
    int ret;
    ((void) cnt);
    ((void) params);

#if defined(TEST_SUITE_ACTIVE)
    if( strcmp( params[0], "base64_encode" ) == 0 )
    {

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;
        int param4;

        if( cnt != 5 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 5 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );
        if( verify_int( params[4], &param4 ) != 0 ) return( 2 );

        test_suite_base64_encode( param1, param2, param3, param4 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "base64_decode" ) == 0 )
    {

        char *param1 = params[1];
        char *param2 = params[2];
        int param3;

        if( cnt != 4 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 4 );
            return( 2 );
        }

        if( verify_string( &param1 ) != 0 ) return( 2 );
        if( verify_string( &param2 ) != 0 ) return( 2 );
        if( verify_int( params[3], &param3 ) != 0 ) return( 2 );

        test_suite_base64_decode( param1, param2, param3 );
        return ( 0 );

        return ( 3 );
    }
    else
    if( strcmp( params[0], "base64_selftest" ) == 0 )
    {
    #ifdef POLARSSL_SELF_TEST


        if( cnt != 1 )
        {
            fprintf( stderr, "\nIncorrect argument count (%d != %d)\n", cnt, 1 );
            return( 2 );
        }


        test_suite_base64_selftest(  );
        return ( 0 );
    #endif /* POLARSSL_SELF_TEST */

        return ( 3 );
    }
    else

    {
        fprintf( stdout, "FAILED\nSkipping unknown test function '%s'\n", params[0] );
        fflush( stdout );
        return( 1 );
    }
#else
    return( 3 );
#endif
    return( ret );
}

int get_line( FILE *f, char *buf, size_t len )
{
    char *ret;

    ret = fgets( buf, len, f );
    if( ret == NULL )
        return( -1 );

    if( strlen( buf ) && buf[strlen(buf) - 1] == '\n' )
        buf[strlen(buf) - 1] = '\0';
    if( strlen( buf ) && buf[strlen(buf) - 1] == '\r' )
        buf[strlen(buf) - 1] = '\0';

    return( 0 );
}

int parse_arguments( char *buf, size_t len, char *params[50] )
{
    int cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < buf + len )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    // Replace newlines, question marks and colons in strings
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *(p + 1) == 'n' )
            {
                p += 2;
                *(q++) = '\n';
            }
            else if( *p == '\\' && *(p + 1) == ':' )
            {
                p += 2;
                *(q++) = ':';
            }
            else if( *p == '\\' && *(p + 1) == '?' )
            {
                p += 2;
                *(q++) = '?';
            }
            else
                *(q++) = *(p++);
        }
        *q = '\0';
    }

    return( cnt );
}

int main()
{
    int ret, i, cnt, total_errors = 0, total_tests = 0, total_skipped = 0;
    const char *filename = "suites/test_suite_base64.data";
    FILE *file;
    char buf[5000];
    char *params[50];

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[1000000];
    memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    file = fopen( filename, "r" );
    if( file == NULL )
    {
        fprintf( stderr, "Failed to open\n" );
        return( 1 );
    }

    while( !feof( file ) )
    {
        int skip = 0;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        fprintf( stdout, "%s%.66s", test_errors ? "\n" : "", buf );
        fprintf( stdout, " " );
        for( i = strlen( buf ) + 1; i < 67; i++ )
            fprintf( stdout, "." );
        fprintf( stdout, " " );
        fflush( stdout );

        total_tests++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        cnt = parse_arguments( buf, strlen(buf), params );

        if( strcmp( params[0], "depends_on" ) == 0 )
        {
            for( i = 1; i < cnt; i++ )
                if( dep_check( params[i] ) != 0 )
                    skip = 1;

            if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen(buf), params );
        }

        if( skip == 0 )
        {
            test_errors = 0;
            ret = dispatch_test( cnt, params );
        }

        if( skip == 1 || ret == 3 )
        {
            total_skipped++;
            fprintf( stdout, "----\n" );
            fflush( stdout );
        }
        else if( ret == 0 && test_errors == 0 )
        {
            fprintf( stdout, "PASS\n" );
            fflush( stdout );
        }
        else if( ret == 2 )
        {
            fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
            fclose(file);
            exit( 2 );
        }
        else
            total_errors++;

        if( ( ret = get_line( file, buf, sizeof(buf) ) ) != 0 )
            break;
        if( strlen(buf) != 0 )
        {
            fprintf( stderr, "Should be empty %d\n", (int) strlen(buf) );
            return( 1 );
        }
    }
    fclose(file);

    fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        fprintf( stdout, "PASSED" );
    else
        fprintf( stdout, "FAILED" );

    fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#if defined(POLARSSL_MEMORY_DEBUG)
    memory_buffer_alloc_status();
#endif
    memory_buffer_alloc_free();
#endif

    return( total_errors != 0 );
}


