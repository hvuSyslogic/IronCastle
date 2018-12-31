using org.bouncycastle.util;

namespace org.bouncycastle.crypto.modes.gcm
{
		
	public class Tables8kGCMMultiplier : GCMMultiplier
	{
		private byte[] H;
		private ulong[][][] T;

		public virtual void init(byte[] H)
		{
			if (T == null)
			{
				T = RectangularArrays.ReturnRectangularULongArray(32, 16, 2);
			}
			else if (Arrays.areEqual(this.H, H))
			{
				return;
			}

			this.H = Arrays.clone(H);

			for (int i = 0; i < 32; ++i)
			{
				ulong[][] t = T[i];

				// t[0] = 0

				if (i == 0)
				{
					// t[1] = H.p^3
					GCMUtil.asLongs(this.H, t[1]);
					GCMUtil.multiplyP3(t[1], t[1]);
				}
				else
				{
					// t[1] = T[i-1][1].p^4
					GCMUtil.multiplyP4(T[i - 1][1], t[1]);
				}

				for (int n = 2; n < 16; n += 2)
				{
					// t[2.n] = t[n].p^-1
					GCMUtil.divideP(t[n >> 1], t[n]);

					// t[2.n + 1] = t[2.n] + t[1]
					GCMUtil.xor(t[n], t[1], t[n + 1]);
				}
			}

		}

		public virtual void multiplyH(byte[] x)
		{
	//        long[] z = new long[2];
	//        for (int i = 15; i >= 0; --i)
	//        {
	//            GCMUtil.xor(z, T[i + i + 1][(x[i] & 0x0F)]);
	//            GCMUtil.xor(z, T[i + i    ][(x[i] & 0xF0) >>> 4]);
	//        }
	//        Pack.longToBigEndian(z, x, 0);

			ulong z0 = 0, z1 = 0;

			for (int i = 15; i >= 0; --i)
			{
				ulong[] u = T[i + i + 1][(x[i] & 0x0F)];
				ulong[] v = T[i + i][(x[i] & 0xF0) >> 4];

				z0 ^= u[0] ^ v[0];
				z1 ^= u[1] ^ v[1];
			}

			Pack.ulongToBigEndian(z0, x, 0);
			Pack.ulongToBigEndian(z1, x, 8);
		}
	}

}