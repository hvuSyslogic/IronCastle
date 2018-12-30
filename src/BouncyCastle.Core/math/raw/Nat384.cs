using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.Raw
{
    internal abstract class Nat384
    {
        public static void mul(uint[] x, uint[] y, uint[] zz)
        {
            Nat192.mul(x, y, zz);
            Nat192.mul(x, 6, y, 6, zz, 12);

            uint c18 = Nat192.addToEachOther(zz, 6, zz, 12);
            uint c12 = c18 + Nat192.addTo(zz, 0, zz, 6, 0);
            c18 += Nat192.addTo(zz, 18, zz, 12, c12);

            uint[] dx = Nat192.create(), dy = Nat192.create();
            bool neg = Nat192.diff(x, 6, x, 0, dx, 0) != Nat192.diff(y, 6, y, 0, dy, 0);

            uint[] tt = Nat192.createExt();
            Nat192.mul(dx, dy, tt);

            c18 += neg ? Nat.addTo(12, tt, 0, zz, 6) : (uint)Nat.subFrom(12, tt, 0, zz, 6);
            Nat.addWordAt(24, c18, zz, 18);
        }

        public static void square(uint[] x, uint[] zz)
        {
            Nat192.square(x, zz);
            Nat192.square(x, 6, zz, 12);

            uint c18 = Nat192.addToEachOther(zz, 6, zz, 12);
            uint c12 = c18 + Nat192.addTo(zz, 0, zz, 6, 0);
            c18 += Nat192.addTo(zz, 18, zz, 12, c12);

            uint[] dx = Nat192.create();
            Nat192.diff(x, 6, x, 0, dx, 0);

            uint[] m = Nat192.createExt();
            Nat192.square(dx, m);

            c18 += (uint)Nat.subFrom(12, m, 0, zz, 6);
            Nat.addWordAt(24, c18, zz, 18);
        }
    }
}
