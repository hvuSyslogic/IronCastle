using System;
using System.Diagnostics;
using BouncyCastle.Core.Port;
using org.bouncycastle.util;

namespace Org.BouncyCastle.Math.Raw
{
    internal abstract class Nat128
    {
        private const ulong M = 0xFFFFFFFFUL;

        public static uint add(uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            c += (ulong)x[0] + y[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)x[1] + y[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (ulong)x[2] + y[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (ulong)x[3] + y[3];
            z[3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint addBothTo(uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            c += (ulong)x[0] + y[0] + z[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)x[1] + y[1] + z[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (ulong)x[2] + y[2] + z[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (ulong)x[3] + y[3] + z[3];
            z[3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint addTo(uint[] x, uint[] z)
        {
            ulong c = 0;
            c += (ulong)x[0] + z[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)x[1] + z[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (ulong)x[2] + z[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (ulong)x[3] + z[3];
            z[3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint addTo(uint[] x, int xOff, uint[] z, int zOff, uint cIn)
        {
            ulong c = cIn;
            c += (ulong)x[xOff + 0] + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 1] + z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 2] + z[zOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            c += (ulong)x[xOff + 3] + z[zOff + 3];
            z[zOff + 3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint addToEachOther(uint[] u, int uOff, uint[] v, int vOff)
        {
            ulong c = 0;
            c += (ulong)u[uOff + 0] + v[vOff + 0];
            u[uOff + 0] = (uint)c;
            v[vOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)u[uOff + 1] + v[vOff + 1];
            u[uOff + 1] = (uint)c;
            v[vOff + 1] = (uint)c;
            c >>= 32;
            c += (ulong)u[uOff + 2] + v[vOff + 2];
            u[uOff + 2] = (uint)c;
            v[vOff + 2] = (uint)c;
            c >>= 32;
            c += (ulong)u[uOff + 3] + v[vOff + 3];
            u[uOff + 3] = (uint)c;
            v[vOff + 3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static void copy(uint[] x, uint[] z)
        {
            z[0] = x[0];
            z[1] = x[1];
            z[2] = x[2];
            z[3] = x[3];
        }

        public static void copy(uint[] x, int xOff, uint[] z, int zOff)
        {
            z[zOff + 0] = x[xOff + 0];
            z[zOff + 1] = x[xOff + 1];
            z[zOff + 2] = x[xOff + 2];
            z[zOff + 3] = x[xOff + 3];
        }

        public static void copy64(ulong[] x, ulong[] z)
        {
            z[0] = x[0];
            z[1] = x[1];
        }

        public static void copy64(ulong[] x, int xOff, ulong[] z, int zOff)
        {
            z[zOff + 0] = x[xOff + 0];
            z[zOff + 1] = x[xOff + 1];
        }

        public static uint[] create()
        {
            return new uint[4];
        }

        public static ulong[] create64()
        {
            return new ulong[2];
        }

        public static uint[] createExt()
        {
            return new uint[8];
        }

        public static ulong[] createExt64()
        {
            return new ulong[4];
        }

        public static bool diff(uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            bool pos = gte(x, xOff, y, yOff);
            if (pos)
            {
                sub(x, xOff, y, yOff, z, zOff);
            }
            else
            {
                sub(y, yOff, x, xOff, z, zOff);
            }
            return pos;
        }

        public static bool eq(uint[] x, uint[] y)
        {
            for (int i = 3; i >= 0; --i)
            {
                if (x[i] != y[i])
                    return false;
            }
            return true;
        }

        public static bool eq64(ulong[] x, ulong[] y)
        {
            for (int i = 1; i >= 0; --i)
            {
                if (x[i] != y[i])
                    return false;
            }
            return true;
        }

        public static uint[] fromBigInteger(BigInteger x)
        {
            if (x.signum() < 0 || x.bitLength() > 128)
                throw new ArgumentException();

            uint[] z = create();
            int i = 0;
            while (x.signum() != 0)
            {
                z[i++] = (uint)x.intValue();
                x = x.shiftRight(32);
            }
            return z;
        }

        public static ulong[] fromBigInteger64(BigInteger x)
        {
            if (x.signum() < 0 || x.bitLength() > 128)
                throw new ArgumentException();

            ulong[] z = create64();
            int i = 0;
            while (x.signum() != 0)
            {
                z[i++] = (ulong)x.longValue();
                x = x.shiftRight(64);
            }
            return z;
        }

        public static uint getBit(uint[] x, int bit)
        {
            if (bit == 0)
            {
                return x[0] & 1;
            }
            if ((bit & 127) != bit)
            {
                return 0;
            }
            int w = bit >> 5;
            int b = bit & 31;
            return (x[w] >> b) & 1;
        }

        public static bool gte(uint[] x, uint[] y)
        {
            for (int i = 3; i >= 0; --i)
            {
                uint xI = x[i], yI = y[i];
                if (xI < yI)
                    return false;
                if (xI > yI)
                    return true;
            }
            return true;
        }

        public static bool gte(uint[] x, int xOff, uint[] y, int yOff)
        {
            for (int i = 3; i >= 0; --i)
            {
                uint xI = x[xOff + i], yI = y[yOff + i];
                if (xI < yI)
                    return false;
                if (xI > yI)
                    return true;
            }
            return true;
        }

        public static bool isOne(uint[] x)
        {
            if (x[0] != 1)
            {
                return false;
            }
            for (int i = 1; i < 4; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool isOne64(ulong[] x)
        {
            if (x[0] != 1UL)
            {
                return false;
            }
            for (int i = 1; i < 2; ++i)
            {
                if (x[i] != 0UL)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool isZero(uint[] x)
        {
            for (int i = 0; i < 4; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool isZero64(ulong[] x)
        {
            for (int i = 0; i < 2; ++i)
            {
                if (x[i] != 0UL)
                {
                    return false;
                }
            }
            return true;
        }

        public static void mul(uint[] x, uint[] y, uint[] zz)
        {
            ulong y0 = y[0];
            ulong y1 = y[1];
            ulong y2 = y[2];
            ulong y3 = y[3];

            {
                ulong c = 0, x0 = x[0];
                c += x0 * y0;
                zz[0] = (uint)c;
                c >>= 32;
                c += x0 * y1;
                zz[1] = (uint)c;
                c >>= 32;
                c += x0 * y2;
                zz[2] = (uint)c;
                c >>= 32;
                c += x0 * y3;
                zz[3] = (uint)c;
                c >>= 32;
                zz[4] = (uint)c;
            }

            for (int i = 1; i < 4; ++i)
            {
                ulong c = 0, xI = x[i];
                c += xI * y0 + zz[i + 0];
                zz[i + 0] = (uint)c;
                c >>= 32;
                c += xI * y1 + zz[i + 1];
                zz[i + 1] = (uint)c;
                c >>= 32;
                c += xI * y2 + zz[i + 2];
                zz[i + 2] = (uint)c;
                c >>= 32;
                c += xI * y3 + zz[i + 3];
                zz[i + 3] = (uint)c;
                c >>= 32;
                zz[i + 4] = (uint)c;
            }
        }

        public static void mul(uint[] x, int xOff, uint[] y, int yOff, uint[] zz, int zzOff)
        {
            ulong y0 = y[yOff + 0];
            ulong y1 = y[yOff + 1];
            ulong y2 = y[yOff + 2];
            ulong y3 = y[yOff + 3];

            {
                ulong c = 0, x0 = x[xOff + 0];
                c += x0 * y0;
                zz[zzOff + 0] = (uint)c;
                c >>= 32;
                c += x0 * y1;
                zz[zzOff + 1] = (uint)c;
                c >>= 32;
                c += x0 * y2;
                zz[zzOff + 2] = (uint)c;
                c >>= 32;
                c += x0 * y3;
                zz[zzOff + 3] = (uint)c;
                c >>= 32;
                zz[zzOff + 4] = (uint)c;
            }

            for (int i = 1; i < 4; ++i)
            {
                ++zzOff;
                ulong c = 0, xI = x[xOff + i];
                c += xI * y0 + zz[zzOff + 0];
                zz[zzOff + 0] = (uint)c;
                c >>= 32;
                c += xI * y1 + zz[zzOff + 1];
                zz[zzOff + 1] = (uint)c;
                c >>= 32;
                c += xI * y2 + zz[zzOff + 2];
                zz[zzOff + 2] = (uint)c;
                c >>= 32;
                c += xI * y3 + zz[zzOff + 3];
                zz[zzOff + 3] = (uint)c;
                c >>= 32;
                zz[zzOff + 4] = (uint)c;
            }
        }

        public static uint mulAddTo(uint[] x, uint[] y, uint[] zz)
        {
            ulong y0 = y[0];
            ulong y1 = y[1];
            ulong y2 = y[2];
            ulong y3 = y[3];

            ulong zc = 0;
            for (int i = 0; i < 4; ++i)
            {
                ulong c = 0, xI = x[i];
                c += xI * y0 + zz[i + 0];
                zz[i + 0] = (uint)c;
                c >>= 32;
                c += xI * y1 + zz[i + 1];
                zz[i + 1] = (uint)c;
                c >>= 32;
                c += xI * y2 + zz[i + 2];
                zz[i + 2] = (uint)c;
                c >>= 32;
                c += xI * y3 + zz[i + 3];
                zz[i + 3] = (uint)c;
                c >>= 32;
                c += zc + zz[i + 4];
                zz[i + 4] = (uint)c;
                zc = c >> 32;
            }
            return (uint)zc;
        }

        public static uint mulAddTo(uint[] x, int xOff, uint[] y, int yOff, uint[] zz, int zzOff)
        {
            ulong y0 = y[yOff + 0];
            ulong y1 = y[yOff + 1];
            ulong y2 = y[yOff + 2];
            ulong y3 = y[yOff + 3];

            ulong zc = 0;
            for (int i = 0; i < 4; ++i)
            {
                ulong c = 0, xI = x[xOff + i];
                c += xI * y0 + zz[zzOff + 0];
                zz[zzOff + 0] = (uint)c;
                c >>= 32;
                c += xI * y1 + zz[zzOff + 1];
                zz[zzOff + 1] = (uint)c;
                c >>= 32;
                c += xI * y2 + zz[zzOff + 2];
                zz[zzOff + 2] = (uint)c;
                c >>= 32;
                c += xI * y3 + zz[zzOff + 3];
                zz[zzOff + 3] = (uint)c;
                c >>= 32;
                c += zc + zz[zzOff + 4];
                zz[zzOff + 4] = (uint)c;
                zc = c >> 32;
                ++zzOff;
            }
            return (uint)zc;
        }

        public static ulong mul33Add(uint w, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            Debug.Assert(w >> 31 == 0);

            ulong c = 0, wVal = w;
            ulong x0 = x[xOff + 0];
            c += wVal * x0 + y[yOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            ulong x1 = x[xOff + 1];
            c += wVal * x1 + x0 + y[yOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            ulong x2 = x[xOff + 2];
            c += wVal * x2 + x1 + y[yOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            ulong x3 = x[xOff + 3];
            c += wVal * x3 + x2 + y[yOff + 3];
            z[zOff + 3] = (uint)c;
            c >>= 32;
            c += x3;
            return c;
        }

        public static uint mulWordAddExt(uint x, uint[] yy, int yyOff, uint[] zz, int zzOff)
        {
            Debug.Assert(yyOff <= 4);
            Debug.Assert(zzOff <= 4);

            ulong c = 0, xVal = x;
            c += xVal * yy[yyOff + 0] + zz[zzOff + 0];
            zz[zzOff + 0] = (uint)c;
            c >>= 32;
            c += xVal * yy[yyOff + 1] + zz[zzOff + 1];
            zz[zzOff + 1] = (uint)c;
            c >>= 32;
            c += xVal * yy[yyOff + 2] + zz[zzOff + 2];
            zz[zzOff + 2] = (uint)c;
            c >>= 32;
            c += xVal * yy[yyOff + 3] + zz[zzOff + 3];
            zz[zzOff + 3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint mul33DWordAdd(uint x, ulong y, uint[] z, int zOff)
        {
            Debug.Assert(x >> 31 == 0);
            Debug.Assert(zOff <= 0);
            ulong c = 0, xVal = x;
            ulong y00 = y & M;
            c += xVal * y00 + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            ulong y01 = y >> 32;
            c += xVal * y01 + y00 + z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += y01 + z[zOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            c += z[zOff + 3];
            z[zOff + 3] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        public static uint mul33WordAdd(uint x, uint y, uint[] z, int zOff)
        {
            Debug.Assert(x >> 31 == 0);
            Debug.Assert(zOff <= 1);
            ulong c = 0, yVal = y;
            c += yVal * x + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += yVal + z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += z[zOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Nat.incAt(4, z, zOff, 3);
        }

        public static uint mulWordDwordAdd(uint x, ulong y, uint[] z, int zOff)
        {
            Debug.Assert(zOff <= 1);
            ulong c = 0, xVal = x;
            c += xVal * y + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += xVal * (y >> 32) + z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += z[zOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Nat.incAt(4, z, zOff, 3);
        }

        public static uint mulWordsAdd(uint x, uint y, uint[] z, int zOff)
        {
            Debug.Assert(zOff <= 2);

            ulong c = 0, xVal = x, yVal = y;
            c += yVal * xVal + z[zOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += z[zOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : Nat.incAt(4, z, zOff, 2);
        }

        public static uint mulWord(uint x, uint[] y, uint[] z, int zOff)
        {
            ulong c = 0, xVal = x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < 4);
            return (uint)c;
        }

        public static void square(uint[] x, uint[] zz)
        {
            ulong x0 = x[0];
            ulong zz1;

            uint c = 0, w;
            {
                int i = 3, j = 8;
                do
                {
                    ulong xVal = x[i--];
                    ulong p = xVal * xVal;
                    zz[--j] = (c << 31) | (uint)(p >> 33);
                    zz[--j] = (uint)(p >> 1);
                    c = (uint)p;
                }
                while (i > 0);

                {
                    ulong p = x0 * x0;
                    zz1 = c << 31 | (p >> 33);
                    zz[0] = (uint)p;
                    c = (uint)(p >> 32) & 1;
                }
            }

            ulong x1 = x[1];
            ulong zz2 = zz[2];

            {
                zz1 += x1 * x0;
                w = (uint)zz1;
                zz[1] = (w << 1) | c;
                c = w >> 31;
                zz2 += zz1 >> 32;
            }

            ulong x2 = x[2];
            ulong zz3 = zz[3];
            ulong zz4 = zz[4];
            {
                zz2 += x2 * x0;
                w = (uint)zz2;
                zz[2] = (w << 1) | c;
                c = w >> 31;
                zz3 += (zz2 >> 32) + x2 * x1;
                zz4 += zz3 >> 32;
                zz3 &= M;
            }

            ulong x3 = x[3];
            ulong zz5 = zz[5] + (zz4 >> 32); zz4 &= M;
            ulong zz6 = zz[6] + (zz5 >> 32); zz5 &= M;
            {
                zz3 += x3 * x0;
                w = (uint)zz3;
                zz[3] = (w << 1) | c;
                c = w >> 31;
                zz4 += (zz3 >> 32) + x3 * x1;
                zz5 += (zz4 >> 32) + x3 * x2;
                zz6 += zz5 >> 32;
            }

            w = (uint)zz4;
            zz[4] = (w << 1) | c;
            c = w >> 31;
            w = (uint)zz5;
            zz[5] = (w << 1) | c;
            c = w >> 31;
            w = (uint)zz6;
            zz[6] = (w << 1) | c;
            c = w >> 31;
            w = zz[7] + (uint)(zz6 >> 32);
            zz[7] = (w << 1) | c;
        }

        public static void square(uint[] x, int xOff, uint[] zz, int zzOff)
        {
            ulong x0 = x[xOff + 0];
            ulong zz1;

            uint c = 0, w;
            {
                int i = 3, j = 8;
                do
                {
                    ulong xVal = x[xOff + i--];
                    ulong p = xVal * xVal;
                    zz[zzOff + --j] = (c << 31) | (uint)(p >> 33);
                    zz[zzOff + --j] = (uint)(p >> 1);
                    c = (uint)p;
                }
                while (i > 0);

                {
                    ulong p = x0 * x0;
                    zz1 = c << 31 | (p >> 33);
                    zz[zzOff + 0] = (uint)p;
                    c = (uint)(p >> 32) & 1;
                }
            }

            ulong x1 = x[xOff + 1];
            ulong zz2 = zz[zzOff + 2];

            {
                zz1 += x1 * x0;
                w = (uint)zz1;
                zz[zzOff + 1] = (w << 1) | c;
                c = w >> 31;
                zz2 += zz1 >> 32;
            }

            ulong x2 = x[xOff + 2];
            ulong zz3 = zz[zzOff + 3];
            ulong zz4 = zz[zzOff + 4];
            {
                zz2 += x2 * x0;
                w = (uint)zz2;
                zz[zzOff + 2] = (w << 1) | c;
                c = w >> 31;
                zz3 += (zz2 >> 32) + x2 * x1;
                zz4 += zz3 >> 32;
                zz3 &= M;
            }

            ulong x3 = x[xOff + 3];
            ulong zz5 = zz[zzOff + 5] + (zz4 >> 32); zz4 &= M;
            ulong zz6 = zz[zzOff + 6] + (zz5 >> 32); zz5 &= M;
            {
                zz3 += x3 * x0;
                w = (uint)zz3;
                zz[zzOff + 3] = (w << 1) | c;
                c = w >> 31;
                zz4 += (zz3 >> 32) + x3 * x1;
                zz5 += (zz4 >> 32) + x3 * x2;
                zz6 += zz5 >> 32;
            }

            w = (uint)zz4;
            zz[zzOff + 4] = (w << 1) | c;
            c = w >> 31;
            w = (uint)zz5;
            zz[zzOff + 5] = (w << 1) | c;
            c = w >> 31;
            w = (uint)zz6;
            zz[zzOff + 6] = (w << 1) | c;
            c = w >> 31;
            w = zz[zzOff + 7] + (uint)(zz6 >> 32);
            zz[zzOff + 7] = (w << 1) | c;
        }

        public static int sub(uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            c += (long)x[0] - y[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)x[1] - y[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (long)x[2] - y[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (long)x[3] - y[3];
            z[3] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static int sub(uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            long c = 0;
            c += (long)x[xOff + 0] - y[yOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (long)x[xOff + 1] - y[yOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += (long)x[xOff + 2] - y[yOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            c += (long)x[xOff + 3] - y[yOff + 3];
            z[zOff + 3] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static int subBothFrom(uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            c += (long)z[0] - x[0] - y[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - x[1] - y[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (long)z[2] - x[2] - y[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (long)z[3] - x[3] - y[3];
            z[3] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static int subFrom(uint[] x, uint[] z)
        {
            long c = 0;
            c += (long)z[0] - x[0];
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - x[1];
            z[1] = (uint)c;
            c >>= 32;
            c += (long)z[2] - x[2];
            z[2] = (uint)c;
            c >>= 32;
            c += (long)z[3] - x[3];
            z[3] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static int subFrom(uint[] x, int xOff, uint[] z, int zOff)
        {
            long c = 0;
            c += (long)z[zOff + 0] - x[xOff + 0];
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + 1] - x[xOff + 1];
            z[zOff + 1] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + 2] - x[xOff + 2];
            z[zOff + 2] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + 3] - x[xOff + 3];
            z[zOff + 3] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        public static BigInteger toBigInteger(uint[] x)
        {
            byte[] bs = new byte[16];
            for (int i = 0; i < 4; ++i)
            {
                uint xI = x[i];
                if (xI != 0)
                {
                    Pack.uintToBigEndian(xI, bs, (3 - i) << 2);
                }
            }
            return new BigInteger(1, bs);
        }

        public static BigInteger toBigInteger64(ulong[] x)
        {
            byte[] bs = new byte[16];
            for (int i = 0; i < 2; ++i)
            {
                ulong xI = x[i];
                if (xI != 0UL)
                {
                    Pack.ulongToBigEndian(xI, bs, (1 - i) << 3);
                }
            }
            return new BigInteger(1, bs);
        }

        public static void zero(uint[] z)
        {
            z[0] = 0;
            z[1] = 0;
            z[2] = 0;
            z[3] = 0;
        }
    }
}
