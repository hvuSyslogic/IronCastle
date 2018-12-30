using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.Raw
{
    internal abstract class Nat512
    {
        public static void mul(uint[] x, uint[] y, uint[] zz)
        {
            Nat256.mul(x, y, zz);
            Nat256.mul(x, 8, y, 8, zz, 16);

            uint c24 = Nat256.addToEachOther(zz, 8, zz, 16);
            uint c16 = c24 + Nat256.addTo(zz, 0, zz, 8, 0);
            c24 += Nat256.addTo(zz, 24, zz, 16, c16);

            uint[] dx = Nat256.create(), dy = Nat256.create();
            bool neg = Nat256.diff(x, 8, x, 0, dx, 0) != Nat256.diff(y, 8, y, 0, dy, 0);

            uint[] tt = Nat256.createExt();
            Nat256.mul(dx, dy, tt);

            c24 += neg ? Nat.addTo(16, tt, 0, zz, 8) : (uint)Nat.subFrom(16, tt, 0, zz, 8);
            Nat.addWordAt(32, c24, zz, 24); 
        }

        public static void square(uint[] x, uint[] zz)
        {
            Nat256.square(x, zz);
            Nat256.square(x, 8, zz, 16);

            uint c24 = Nat256.addToEachOther(zz, 8, zz, 16);
            uint c16 = c24 + Nat256.addTo(zz, 0, zz, 8, 0);
            c24 += Nat256.addTo(zz, 24, zz, 16, c16);

            uint[] dx = Nat256.create();
            Nat256.diff(x, 8, x, 0, dx, 0);

            uint[] m = Nat256.createExt();
            Nat256.square(dx, m);

            c24 += (uint)Nat.subFrom(16, m, 0, zz, 8);
            Nat.addWordAt(32, c24, zz, 24); 
        }
    }
}
