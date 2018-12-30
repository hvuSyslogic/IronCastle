using System.Diagnostics;
using BouncyCastle.Core.Port;
using Org.BouncyCastle.Math.Raw;

namespace org.bouncycastle.math.ec.custom.djb
{
    internal class Curve25519Field
    {
        // 2^255 - 2^4 - 2^1 - 1
        internal static readonly uint[] P = new uint[]{ 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0x7FFFFFFF };
        private const uint P7 = 0x7FFFFFFF;
        private static readonly uint[] PExt = new uint[]{ 0x00000169, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0x3FFFFFFF };
        private const uint PInv = 0x13;

        public static void add(uint[] x, uint[] y, uint[] z)
        {
            Nat256.add(x, y, z);
            if (Nat256.gte(z, P))
            {
                subPFrom(z);
            }
        }

        public static void addExt(uint[] xx, uint[] yy, uint[] zz)
        {
            Nat.add(16, xx, yy, zz);
            if (Nat.gte(16, zz, PExt))
            {
                subPExtFrom(zz);
            }
        }

        public static void addOne(uint[] x, uint[] z)
        {
            Nat.inc(8, x, z);
            if (Nat256.gte(z, P))
            {
                subPFrom(z);
            }
        }

        public static uint[] fromBigInteger(BigInteger x)
        {
            uint[] z = Nat256.fromBigInteger(x);
            while (Nat256.gte(z, P))
            {
                Nat256.subFrom(P, z);
            }
            return z;
        }

        public static void half(uint[] x, uint[] z)
        {
            if ((x[0] & 1) == 0)
            {
                Nat.shiftDownBit(8, x, 0, z);
            }
            else
            {
                Nat256.add(x, P, z);
                Nat.shiftDownBit(8, z, 0);
            }
        }

        public static void multiply(uint[] x, uint[] y, uint[] z)
        {
            uint[] tt = Nat256.createExt();
            Nat256.mul(x, y, tt);
            reduce(tt, z);
        }

        public static void multiplyAddToExt(uint[] x, uint[] y, uint[] zz)
        {
            Nat256.mulAddTo(x, y, zz);
            if (Nat.gte(16, zz, PExt))
            {
                subPExtFrom(zz);
            }
        }

        public static void negate(uint[] x, uint[] z)
        {
            if (Nat256.isZero(x))
            {
                Nat256.zero(z);
            }
            else
            {
                Nat256.sub(P, x, z);
            }
        }

        public static void reduce(uint[] xx, uint[] z)
        {
            Debug.Assert(xx[15] >> 30 == 0);

            uint xx07 = xx[7];
            Nat.shiftUpBit(8, xx, 8, xx07, z, 0);
            uint c = Nat256.mulByWordAddTo(PInv, xx, z) << 1;
            uint z7 = z[7];
            c += (z7 >> 31) - (xx07 >> 31);
            z7 &= P7;
            z7 += Nat.addWordTo(7, c * PInv, z);
            z[7] = z7;
            if (z7 >= P7 && Nat256.gte(z, P))
            {
                subPFrom(z);
            }
        }

        public static void reduce27(uint x, uint[] z)
        {
            Debug.Assert(x >> 26 == 0);

            uint z7 = z[7];
            uint c = (x << 1 | z7 >> 31);
            z7 &= P7;
            z7 += Nat.addWordTo(7, c * PInv, z);
            z[7] = z7;
            if (z7 >= P7 && Nat256.gte(z, P))
            {
                subPFrom(z);
            }
        }

        public static void square(uint[] x, uint[] z)
        {
            uint[] tt = Nat256.createExt();
            Nat256.square(x, tt);
            reduce(tt, z);
        }

        public static void squareN(uint[] x, int n, uint[] z)
        {
            Debug.Assert(n > 0);

            uint[] tt = Nat256.createExt();
            Nat256.square(x, tt);
            reduce(tt, z);

            while (--n > 0)
            {
                Nat256.square(z, tt);
                reduce(tt, z);
            }
        }

        public static void subtract(uint[] x, uint[] y, uint[] z)
        {
            int c = Nat256.sub(x, y, z);
            if (c != 0)
            {
                addPTo(z);
            }
        }

        public static void subtractExt(uint[] xx, uint[] yy, uint[] zz)
        {
            int c = Nat.sub(16, xx, yy, zz);
            if (c != 0)
            {
                addPExtTo(zz);
            }
        }

        public static void twice(uint[] x, uint[] z)
        {
            Nat.shiftUpBit(8, x, 0, z);
            if (Nat256.gte(z, P))
            {
                subPFrom(z);
            }
        }

        private static uint addPTo(uint[] z)
        {
            long c = (long)z[0] - PInv;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.decAt(7, z, 1);
            }
            c += (long)z[7] + (P7 + 1);
            z[7] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        private static uint addPExtTo(uint[] zz)
        {
            long c = (long)zz[0] + PExt[0];
            zz[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.incAt(8, zz, 1);
            }
            c += (long)zz[8] - PInv;
            zz[8] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.decAt(15, zz, 9);
            }
            c += (long)zz[15] + (PExt[15] + 1);
            zz[15] = (uint)c;
            c >>= 32;
            return (uint)c;
        }

        private static int subPFrom(uint[] z)
        {
            long c = (long)z[0] + PInv;
            z[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.incAt(7, z, 1);
            }
            c += (long)z[7] - (P7 + 1);
            z[7] = (uint)c;
            c >>= 32;
            return (int)c;
        }

        private static int subPExtFrom(uint[] zz)
        {
            long c = (long)zz[0] - PExt[0];
            zz[0] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.decAt(8, zz, 1);
            }
            c += (long)zz[8] + PInv;
            zz[8] = (uint)c;
            c >>= 32;
            if (c != 0)
            {
                c = Nat.incAt(15, zz, 9);
            }
            c += (long)zz[15] - (PExt[15] + 1);
            zz[15] = (uint)c;
            c >>= 32;
            return (int)c;
        }
    }
}