using System;
using System.Diagnostics;
using BouncyCastle.Core.Port;
using org.bouncycastle.util;

namespace Org.BouncyCastle.Math.Raw
{
    internal abstract class Nat
    {
        private const ulong M = 0xFFFFFFFFUL;

        public static uint add(int len, uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint add33At(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zPos + 0] + x;
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zPos + 1] + 1;
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zPos + 2);
        }

        public static uint add33At(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zOff + zPos] + x;
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + zPos + 1] + 1;
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zOff, zPos + 2);
        }

        public static uint add33To(int len, uint x, uint[] z)
        {
            ulong c = (ulong)z[0] + x;
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)z[1] + 1;
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, 2);
        }

        public static uint add33To(int len, uint x, uint[] z, int zOff)
        {
            ulong c = (ulong)z[zOff + 0] + x;
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1] + 1;
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zOff, 2);
        }

        public static uint addBothTo(int len, uint[] x, uint[] y, uint[] z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + y[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint addBothTo(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[xOff + i] + y[yOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint addDWordAt(int len, ulong x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zPos + 0] + (x & M);
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zPos + 1] + (x >> 32);
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zPos + 2);
        }

        public static uint addDWordAt(int len, ulong x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            ulong c = (ulong)z[zOff + zPos] + (x & M);
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + zPos + 1] + (x >> 32);
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zOff, zPos + 2);
        }

        public static uint addDWordTo(int len, ulong x, uint[] z)
        {
            ulong c = (ulong)z[0] + (x & M);
            z[0] = (uint)c;
            c >>= 32;
            c += (ulong)z[1] + (x >> 32);
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, 2);
        }

        public static uint addDWordTo(int len, ulong x, uint[] z, int zOff)
        {
            ulong c = (ulong)z[zOff + 0] + (x & M);
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (ulong)z[zOff + 1] + (x >> 32);
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zOff, 2);
        }

        public static uint addTo(int len, uint[] x, uint[] z)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + z[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint addTo(int len, uint[] x, int xOff, uint[] z, int zOff)
        {
            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[xOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static uint addWordAt(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            ulong c = (ulong)x + z[zPos];
            z[zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zPos + 1);
        }

        public static uint addWordAt(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            ulong c = (ulong)x + z[zOff + zPos];
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zOff, zPos + 1);
        }

        public static uint addWordTo(int len, uint x, uint[] z)
        {
            ulong c = (ulong)x + z[0];
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, 1);
        }

        public static uint addWordTo(int len, uint x, uint[] z, int zOff)
        {
            ulong c = (ulong)x + z[zOff];
            z[zOff] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zOff, 1);
        }

        public static uint cAdd(int len, int mask, uint[] x, uint[] y, uint[] z)
        {
            uint MASK = (uint)-(mask & 1);

            ulong c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (ulong)x[i] + (y[i] & MASK);
                z[i] = (uint)c;
                c >>= 32;
            }
            return (uint)c;
        }

        public static void cMov(int len, int mask, uint[] x, int xOff, uint[] z, int zOff)
        {
            uint MASK = (uint)-(mask & 1);

            for (int i = 0; i < len; ++i)
            {
                uint zI = z[zOff + i], diff = zI ^ x[xOff + i];
                zI ^= (diff & MASK);
                z[zOff + i] = zI;
            }

            //uint half = 0x55555555U, rest = half << (-(int)MASK);

            //for (int i = 0; i < len; ++i)
            //{
            //    uint z_i = z[zOff + i], diff = z_i ^ x[xOff + i];
            //    z_i ^= (diff & half);
            //    z_i ^= (diff & rest);
            //    z[zOff + i] = z_i;
            //}
        }

        public static void cMov(int len, int mask, int[] x, int xOff, int[] z, int zOff)
        {
            mask = -(mask & 1);

            for (int i = 0; i < len; ++i)
            {
                int zI = z[zOff + i], diff = zI ^ x[xOff + i];
                zI ^= (diff & mask);
                z[zOff + i] = zI;
            }

            //int half = 0x55555555, rest = half << (-mask);

            //for (int i = 0; i < len; ++i)
            //{
            //    int z_i = z[zOff + i], diff = z_i ^ x[xOff + i];
            //    z_i ^= (diff & half);
            //    z_i ^= (diff & rest);
            //    z[zOff + i] = z_i;
            //}
        }

        public static void copy(int len, uint[] x, uint[] z)
        {
            Array.Copy(x, 0, z, 0, len);
        }

        public static uint[] copy(int len, uint[] x)
        {
            uint[] z = new uint[len];
            Array.Copy(x, 0, z, 0, len);
            return z;
        }

        public static void copy(int len, uint[] x, int xOff, uint[] z, int zOff)
        {
            Array.Copy(x, xOff, z, zOff, len);
        }

        public static uint[] create(int len)
        {
            return new uint[len];
        }

        public static ulong[] create64(int len)
        {
            return new ulong[len];
        }

        public static int dec(int len, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                {
                    return 0;
                }
            }
            return -1;
        }

        public static int dec(int len, uint[] x, uint[] z)
        {
            int i = 0;
            while (i < len)
            {
                uint c = x[i] - 1;
                z[i] = c;
                ++i;
                if (c != uint.MaxValue)
                {
                    while (i < len)
                    {
                        z[i] = x[i];
                        ++i;
                    }
                    return 0;
                }
            }
            return -1;
        }

        public static int decAt(int len, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (--z[i] != uint.MaxValue)
                {
                    return 0;
                }
            }
            return -1;
        }

        public static int decAt(int len, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (--z[zOff + i] != uint.MaxValue)
                {
                    return 0;
                }
            }
            return -1;
        }

        public static bool eq(int len, uint[] x, uint[] y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                if (x[i] != y[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static uint[] fromBigInteger(int bits, BigInteger x)
        {
            if (x.signum() < 0 || x.bitLength() > bits)
                throw new ArgumentException();

            int len = (bits + 31) >> 5;
            uint[] z = create(len);
            int i = 0;
            while (x.signum() != 0)
            {
                z[i++] = (uint)x.intValue();
                x = x.shiftRight(32);
            }
            return z;
        }

        public static uint getBit(uint[] x, int bit)
        {
            if (bit == 0)
            {
                return x[0] & 1;
            }
            int w = bit >> 5;
            if (w < 0 || w >= x.Length)
            {
                return 0;
            }
            int b = bit & 31;
            return (x[w] >> b) & 1;
        }

        public static bool gte(int len, uint[] x, uint[] y)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                uint xI = x[i], yI = y[i];
                if (xI < yI)
                    return false;
                if (xI > yI)
                    return true;
            }
            return true;
        }

        public static uint inc(int len, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static uint inc(int len, uint[] x, uint[] z)
        {
            int i = 0;
            while (i < len)
            {
                uint c = x[i] + 1;
                z[i] = c;
                ++i;
                if (c != 0)
                {
                    while (i < len)
                    {
                        z[i] = x[i];
                        ++i;
                    }
                    return 0;
                }
            }
            return 1;
        }

        public static uint incAt(int len, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (++z[i] != uint.MinValue)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static uint incAt(int len, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= len);
            for (int i = zPos; i < len; ++i)
            {
                if (++z[zOff + i] != uint.MinValue)
                {
                    return 0;
                }
            }
            return 1;
        }

        public static bool isOne(int len, uint[] x)
        {
            if (x[0] != 1)
            {
                return false;
            }
            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool isZero(int len, uint[] x)
        {
            if (x[0] != 0)
            {
                return false;
            }
            for (int i = 1; i < len; ++i)
            {
                if (x[i] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static void mul(int len, uint[] x, uint[] y, uint[] zz)
        {
            zz[len] = mulWord(len, x[0], y, zz);

            for (int i = 1; i < len; ++i)
            {
                zz[i + len] = mulWordAddTo(len, x[i], y, 0, zz, i);
            }
        }

        public static void mul(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] zz, int zzOff)
        {
            zz[zzOff + len] = mulWord(len, x[xOff], y, yOff, zz, zzOff);

            for (int i = 1; i < len; ++i)
            {
                zz[zzOff + i + len] = mulWordAddTo(len, x[xOff + i], y, yOff, zz, zzOff + i);
            }
        }

        public static void mul(uint[] x, int xOff, int xLen, uint[] y, int yOff, int yLen, uint[] zz, int zzOff)
        {
            zz[zzOff + yLen] = mulWord(yLen, x[xOff], y, yOff, zz, zzOff);

            for (int i = 1; i < xLen; ++i)
            {
                zz[zzOff + i + yLen] = mulWordAddTo(yLen, x[xOff + i], y, yOff, zz, zzOff + i);
            }
        }

        public static uint mulAddTo(int len, uint[] x, uint[] y, uint[] zz)
        {
            ulong zc = 0;
            for (int i = 0; i < len; ++i)
            {
                ulong c = mulWordAddTo(len, x[i], y, 0, zz, i) & M;
                c += zc + (zz[i + len] & M);
                zz[i + len] = (uint)c;
                zc = c >> 32;
            }
            return (uint)zc;
        }

        public static uint mulAddTo(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] zz, int zzOff)
        {
            ulong zc = 0;
            for (int i = 0; i < len; ++i)
            {
                ulong c = mulWordAddTo(len, x[xOff + i], y, yOff, zz, zzOff) & M;
                c += zc + (zz[zzOff + len] & M);
                zz[zzOff + len] = (uint)c;
                zc = c >> 32;
                ++zzOff;
            }
            return (uint)zc;
        }

        public static uint mul31BothAdd(int len, uint a, uint[] x, uint b, uint[] y, uint[] z, int zOff)
        {
            ulong c = 0, aVal = (ulong)a, bVal = (ulong)b;
            int i = 0;
            do
            {
                c += aVal * x[i] + bVal * y[i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint mulWord(int len, uint x, uint[] y, uint[] z)
        {
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint mulWord(int len, uint x, uint[] y, int yOff, uint[] z, int zOff)
        {
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * y[yOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint mulWordAddTo(int len, uint x, uint[] y, int yOff, uint[] z, int zOff)
        {
            ulong c = 0, xVal = (ulong)x;
            int i = 0;
            do
            {
                c += xVal * y[yOff + i] + z[zOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            while (++i < len);
            return (uint)c;
        }

        public static uint mulWordDwordAddAt(int len, uint x, ulong y, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 3));
            ulong c = 0, xVal = (ulong)x;
            c += xVal * (uint)y + z[zPos + 0];
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += xVal * (y >> 32) + z[zPos + 1];
            z[zPos + 1] = (uint)c;
            c >>= 32;
            c += (ulong)z[zPos + 2];
            z[zPos + 2] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : incAt(len, z, zPos + 3);
        }

        public static uint shiftDownBit(int len, uint[] z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        public static uint shiftDownBit(int len, uint[] z, int zOff, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        public static uint shiftDownBit(int len, uint[] x, uint c, uint[] z)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                z[i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        public static uint shiftDownBit(int len, uint[] x, int xOff, uint c, uint[] z, int zOff)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next >> 1) | (c << 31);
                c = next;
            }
            return c << 31;
        }

        public static uint shiftDownBits(int len, uint[] z, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint shiftDownBits(int len, uint[] z, int zOff, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint shiftDownBits(int len, uint[] x, int bits, uint c, uint[] z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[i];
                z[i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint shiftDownBits(int len, uint[] x, int xOff, int bits, uint c, uint[] z, int zOff)
        {
            Debug.Assert(bits > 0 && bits < 32);
            int i = len;
            while (--i >= 0)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next >> bits) | (c << -bits);
                c = next;
            }
            return c << -bits;
        }

        public static uint shiftDownWord(int len, uint[] z, uint c)
        {
            int i = len;
            while (--i >= 0)
            {
                uint next = z[i];
                z[i] = c;
                c = next;
            }
            return c;
        }

        public static uint shiftUpBit(int len, uint[] z, uint c)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = z[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static uint shiftUpBit(int len, uint[] z, int zOff, uint c)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static uint shiftUpBit(int len, uint[] x, uint c, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = x[i];
                z[i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static uint shiftUpBit(int len, uint[] x, int xOff, uint c, uint[] z, int zOff)
        {
            for (int i = 0; i < len; ++i)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next << 1) | (c >> 31);
                c = next;
            }
            return c >> 31;
        }

        public static ulong shiftUpBit64(int len, ulong[] x, int xOff, ulong c, ulong[] z, int zOff)
        {
            for (int i = 0; i < len; ++i)
            {
                ulong next = x[xOff + i];
                z[zOff + i] = (next << 1) | (c >> 63);
                c = next;
            }
            return c >> 63;
        }

        public static uint shiftUpBits(int len, uint[] z, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            for (int i = 0; i < len; ++i)
            {
                uint next = z[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static uint shiftUpBits(int len, uint[] z, int zOff, int bits, uint c)
        {
            Debug.Assert(bits > 0 && bits < 32);
            for (int i = 0; i < len; ++i)
            {
                uint next = z[zOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static ulong shiftUpBits64(int len, ulong[] z, int zOff, int bits, ulong c)
        {
            Debug.Assert(bits > 0 && bits < 64);
            for (int i = 0; i < len; ++i)
            {
                ulong next = z[zOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static uint shiftUpBits(int len, uint[] x, int bits, uint c, uint[] z)
        {
            Debug.Assert(bits > 0 && bits < 32);
            for (int i = 0; i < len; ++i)
            {
                uint next = x[i];
                z[i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static uint shiftUpBits(int len, uint[] x, int xOff, int bits, uint c, uint[] z, int zOff)
        {
            Debug.Assert(bits > 0 && bits < 32);
            for (int i = 0; i < len; ++i)
            {
                uint next = x[xOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static ulong shiftUpBits64(int len, ulong[] x, int xOff, int bits, ulong c, ulong[] z, int zOff)
        {
            Debug.Assert(bits > 0 && bits < 64);
            for (int i = 0; i < len; ++i)
            {
                ulong next = x[xOff + i];
                z[zOff + i] = (next << bits) | (c >> -bits);
                c = next;
            }
            return c >> -bits;
        }

        public static void square(int len, uint[] x, uint[] zz)
        {
            int extLen = len << 1;
            uint c = 0;
            int j = len, k = extLen;
            do
            {
                ulong xVal = (ulong)x[--j];
                ulong p = xVal * xVal;
                zz[--k] = (c << 31) | (uint)(p >> 33);
                zz[--k] = (uint)(p >> 1);
                c = (uint)p;
            }
            while (j > 0);

            for (int i = 1; i < len; ++i)
            {
                c = squareWordAdd(x, i, zz);
                addWordAt(extLen, c, zz, i << 1);
            }

            shiftUpBit(extLen, zz, x[0] << 31);
        }

        public static void square(int len, uint[] x, int xOff, uint[] zz, int zzOff)
        {
            int extLen = len << 1;
            uint c = 0;
            int j = len, k = extLen;
            do
            {
                ulong xVal = (ulong)x[xOff + --j];
                ulong p = xVal * xVal;
                zz[zzOff + --k] = (c << 31) | (uint)(p >> 33);
                zz[zzOff + --k] = (uint)(p >> 1);
                c = (uint)p;
            }
            while (j > 0);

            for (int i = 1; i < len; ++i)
            {
                c = squareWordAdd(x, xOff, i, zz, zzOff);
                addWordAt(extLen, c, zz, zzOff, i << 1);
            }

            shiftUpBit(extLen, zz, zzOff, x[xOff] << 31);
        }

        public static uint squareWordAdd(uint[] x, int xPos, uint[] z)
        {
            ulong c = 0, xVal = (ulong)x[xPos];
            int i = 0;
            do
            {
                c += xVal * x[i] + z[xPos + i];
                z[xPos + i] = (uint)c;
                c >>= 32;
            }
            while (++i < xPos);
            return (uint)c;
        }

        public static uint squareWordAdd(uint[] x, int xOff, int xPos, uint[] z, int zOff)
        {
            ulong c = 0, xVal = (ulong)x[xOff + xPos];
            int i = 0;
            do
            {
                c += xVal * (x[xOff + i] & M) + (z[xPos + zOff] & M);
                z[xPos + zOff] = (uint)c;
                c >>= 32;
                ++zOff;
            }
            while (++i < xPos);
            return (uint)c;
        }

        public static int sub(int len, uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[i] - y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int sub(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)x[xOff + i] - y[yOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }
        public static int sub33At(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zPos + 0] - x;
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zPos + 1] - 1;
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zPos + 2);
        }

        public static int sub33At(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zOff + zPos] - x;
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + zPos + 1] - 1;
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zOff, zPos + 2);
        }

        public static int sub33From(int len, uint x, uint[] z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - 1;
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, 2);
        }

        public static int sub33From(int len, uint x, uint[] z, int zOff)
        {
            long c = (long)z[zOff + 0] - x;
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + 1] - 1;
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zOff, 2);
        }

        public static int subBothFrom(int len, uint[] x, uint[] y, uint[] z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[i] - x[i] - y[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int subBothFrom(int len, uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[zOff + i] - x[xOff + i] - y[yOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int subDWordAt(int len, ulong x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zPos + 0] - (long)(x & M);
            z[zPos + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zPos + 1] - (long)(x >> 32);
            z[zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zPos + 2);
        }

        public static int subDWordAt(int len, ulong x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 2));
            long c = (long)z[zOff + zPos] - (long)(x & M);
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + zPos + 1] - (long)(x >> 32);
            z[zOff + zPos + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z,  zOff, zPos + 2);
        }

        public static int subDWordFrom(int len, ulong x, uint[] z)
        {
            long c = (long)z[0] - (long)(x & M);
            z[0] = (uint)c;
            c >>= 32;
            c += (long)z[1] - (long)(x >> 32);
            z[1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, 2);
        }

        public static int subDWordFrom(int len, ulong x, uint[] z, int zOff)
        {
            long c = (long)z[zOff + 0] - (long)(x & M);
            z[zOff + 0] = (uint)c;
            c >>= 32;
            c += (long)z[zOff + 1] - (long)(x >> 32);
            z[zOff + 1] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zOff, 2);
        }

        public static int subFrom(int len, uint[] x, uint[] z)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[i] - x[i];
                z[i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int subFrom(int len, uint[] x, int xOff, uint[] z, int zOff)
        {
            long c = 0;
            for (int i = 0; i < len; ++i)
            {
                c += (long)z[zOff + i] - x[xOff + i];
                z[zOff + i] = (uint)c;
                c >>= 32;
            }
            return (int)c;
        }

        public static int subWordAt(int len, uint x, uint[] z, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            long c = (long)z[zPos] - x;
            z[zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zPos + 1);
        }

        public static int subWordAt(int len, uint x, uint[] z, int zOff, int zPos)
        {
            Debug.Assert(zPos <= (len - 1));
            long c = (long)z[zOff + zPos] - x;
            z[zOff + zPos] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zOff, zPos + 1);
        }

        public static int subWordFrom(int len, uint x, uint[] z)
        {
            long c = (long)z[0] - x;
            z[0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, 1);
        }

        public static int subWordFrom(int len, uint x, uint[] z, int zOff)
        {
            long c = (long)z[zOff + 0] - x;
            z[zOff + 0] = (uint)c;
            c >>= 32;
            return c == 0 ? 0 : decAt(len, z, zOff, 1);
        }

        public static BigInteger toBigInteger(int len, uint[] x)
        {
            byte[] bs = new byte[len << 2];
            for (int i = 0; i < len; ++i)
            {
                uint xI = x[i];
                if (xI != 0)
                {
                    Pack.uintToBigEndian(xI, bs, (len - 1 - i) << 2);
                }
            }
            return new BigInteger(1, bs);
        }

        public static void zero(int len, uint[] z)
        {
            for (int i = 0; i < len; ++i)
            {
                z[i] = 0;
            }
        }
    }
}
