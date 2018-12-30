namespace org.bouncycastle.crypto.modes.gcm
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;

	public class Tables4kGCMMultiplier : GCMMultiplier
	{
		private byte[] H;
		private long[][] T;

		public virtual void init(byte[] H)
		{
			if (T == null)
			{
				T = RectangularArrays.ReturnRectangularLongArray(256, 2);
			}
			else if (Arrays.areEqual(this.H, H))
			{
				return;
			}

			this.H = Arrays.clone(H);

			// T[0] = 0

			// T[1] = H.p^7
			GCMUtil.asLongs(this.H, T[1]);
			GCMUtil.multiplyP7(T[1], T[1]);

			for (int n = 2; n < 256; n += 2)
			{
				// T[2.n] = T[n].p^-1
				GCMUtil.divideP(T[n >> 1], T[n]);

				// T[2.n + 1] = T[2.n] + T[1]
				GCMUtil.xor(T[n], T[1], T[n + 1]);
			}
		}

		public virtual void multiplyH(byte[] x)
		{
	//        long[] z = new long[2];
	//        GCMUtil.copy(T[x[15] & 0xFF], z);
	//        for (int i = 14; i >= 0; --i)
	//        {
	//            GCMUtil.multiplyP8(z);
	//            GCMUtil.xor(z, T[x[i] & 0xFF]);
	//        }
	//        Pack.longToBigEndian(z, x, 0);

			long[] t = T[x[15] & 0xFF];
			long z0 = t[0], z1 = t[1];

			for (int i = 14; i >= 0; --i)
			{
				t = T[x[i] & 0xFF];

				long c = z1 << 56;
				z1 = t[1] ^ (((long)((ulong)z1 >> 8)) | (z0 << 56));
				z0 = t[0] ^ ((long)((ulong)z0 >> 8)) ^ c ^ ((long)((ulong)c >> 1)) ^ ((long)((ulong)c >> 2)) ^ ((long)((ulong)c >> 7));
			}

			Pack.longToBigEndian(z0, x, 0);
			Pack.longToBigEndian(z1, x, 8);
		}
	}

}