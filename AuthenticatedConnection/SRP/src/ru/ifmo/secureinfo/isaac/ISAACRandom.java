package ru.ifmo.secureinfo.isaac;

/**
 * User: danielpenkin
 * Date: May 8, 2010
 */
public class ISAACRandom {

    /* rand.init() -- initialize
    * rand.val()  -- get a random value
    */

    final static int SIZEL = 8;              /* log of size of rsl[] and mem[] */
    final static int SIZE = 1 << SIZEL;               /* size of rsl[] and mem[] */
    final static int MASK = (SIZE - 1) << 2;            /* for pseudorandom lookup */
    int count;                           /* count through the results in rsl[] */
    int rsl[];                                /* the results given to the user */
    private int mem[];                                   /* the internal state */
    private int a;                                              /* accumulator */
    private int b;                                          /* the last result */
    private int c;              /* counter, guarantees cycle is at least 2^^40 */


    /* no seed, equivalent to randinit(ctx,FALSE) in C */

    ISAACRandom() {
        mem = new int[SIZE];
        rsl = new int[SIZE];
        Init(false);
    }

    /* equivalent to randinit(ctx, TRUE) after putting seed in randctx in C */

    ISAACRandom(int seed[]) {
        mem = new int[SIZE];
        rsl = new int[SIZE];
        for (int i = 0; i < seed.length; ++i) {
            rsl[i] = seed[i];
        }
        Init(true);
    }


    /* Generate 256 results.  This is a fast (not small) implementation. */

    public final void Isaac() {
        int i, j, x, y;

        b += ++c;
        for (i = 0, j = SIZE / 2; i < SIZE / 2;) {
            x = mem[i];
            a ^= a << 13;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

            x = mem[i];
            a ^= a >>> 6;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

            x = mem[i];
            a ^= a << 2;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

            x = mem[i];
            a ^= a >>> 16;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;
        }

        for (j = 0; j < SIZE / 2;) {
            x = mem[i];
            a ^= a << 13;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

            x = mem[i];
            a ^= a >>> 6;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

            x = mem[i];
            a ^= a << 2;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

            x = mem[i];
            a ^= a >>> 16;
            a += mem[j++];
            mem[i] = y = mem[(x & MASK) >> 2] + a + b;
            rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;
        }
    }


    /* initialize, or reinitialize, this instance of rand */

    public final void Init(boolean flag) {
        int i;
        int a, b, c, d, e, f, g, h;
        a = b = c = d = e = f = g = h = 0x9e3779b9;                        /* the golden ratio */

        for (i = 0; i < 4; ++i) {
            a ^= b << 11;
            d += a;
            b += c;
            b ^= c >>> 2;
            e += b;
            c += d;
            c ^= d << 8;
            f += c;
            d += e;
            d ^= e >>> 16;
            g += d;
            e += f;
            e ^= f << 10;
            h += e;
            f += g;
            f ^= g >>> 4;
            a += f;
            g += h;
            g ^= h << 8;
            b += g;
            h += a;
            h ^= a >>> 9;
            c += h;
            a += b;
        }

        for (i = 0; i < SIZE; i += 8) {              /* fill in mem[] with messy stuff */
            if (flag) {
                a += rsl[i];
                b += rsl[i + 1];
                c += rsl[i + 2];
                d += rsl[i + 3];
                e += rsl[i + 4];
                f += rsl[i + 5];
                g += rsl[i + 6];
                h += rsl[i + 7];
            }
            a ^= b << 11;
            d += a;
            b += c;
            b ^= c >>> 2;
            e += b;
            c += d;
            c ^= d << 8;
            f += c;
            d += e;
            d ^= e >>> 16;
            g += d;
            e += f;
            e ^= f << 10;
            h += e;
            f += g;
            f ^= g >>> 4;
            a += f;
            g += h;
            g ^= h << 8;
            b += g;
            h += a;
            h ^= a >>> 9;
            c += h;
            a += b;
            mem[i] = a;
            mem[i + 1] = b;
            mem[i + 2] = c;
            mem[i + 3] = d;
            mem[i + 4] = e;
            mem[i + 5] = f;
            mem[i + 6] = g;
            mem[i + 7] = h;
        }

        if (flag) {           /* second pass makes all of seed affect all of mem */
            for (i = 0; i < SIZE; i += 8) {
                a += mem[i];
                b += mem[i + 1];
                c += mem[i + 2];
                d += mem[i + 3];
                e += mem[i + 4];
                f += mem[i + 5];
                g += mem[i + 6];
                h += mem[i + 7];
                a ^= b << 11;
                d += a;
                b += c;
                b ^= c >>> 2;
                e += b;
                c += d;
                c ^= d << 8;
                f += c;
                d += e;
                d ^= e >>> 16;
                g += d;
                e += f;
                e ^= f << 10;
                h += e;
                f += g;
                f ^= g >>> 4;
                a += f;
                g += h;
                g ^= h << 8;
                b += g;
                h += a;
                h ^= a >>> 9;
                c += h;
                a += b;
                mem[i] = a;
                mem[i + 1] = b;
                mem[i + 2] = c;
                mem[i + 3] = d;
                mem[i + 4] = e;
                mem[i + 5] = f;
                mem[i + 6] = g;
                mem[i + 7] = h;
            }
        }

        Isaac();
        count = SIZE;
    }


    /* Call rand.val() to get a random value */

    public final int val() {
        if (0 == count--) {
            Isaac();
            count = SIZE - 1;
        }
        return rsl[count];
    }

    public static void main(String[] args) {
        ISAACRandom x = new ISAACRandom();
        x.Init(true);
        int val = x.val();
        System.out.println(val + " " + Integer.toHexString(val));
        for (int i = 0; i < 2; ++i) {
            x.Isaac();
            for (int j = 0; j < ISAACRandom.SIZE; ++j) {
                String z = Integer.toHexString(x.rsl[j]);
                while (z.length() < 8) z = "0" + z;
                System.out.print(z);
                if ((j & 7) == 7) System.out.println("");
            }
        }
    }

}