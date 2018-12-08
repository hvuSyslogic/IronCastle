﻿using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.modes.gcm
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class Tables1kGCMExponentiator : GCMExponentiator
	{
		// A lookup table of the power-of-two powers of 'x'
		// - lookupPowX2[i] = x^(2^i)
		private Vector lookupPowX2;

		public virtual void init(byte[] x)
		{
			long[] y = GCMUtil.asLongs(x);
			if (lookupPowX2 != null && Arrays.areEqual(y, (long[])lookupPowX2.elementAt(0)))
			{
				return;
			}

			lookupPowX2 = new Vector(8);
			lookupPowX2.addElement(y);
		}

		public virtual void exponentiateX(long pow, byte[] output)
		{
			long[] y = GCMUtil.oneAsLongs();
			int bit = 0;
			while (pow > 0)
			{
				if ((pow & 1L) != 0)
				{
					ensureAvailable(bit);
					GCMUtil.multiply(y, (long[])lookupPowX2.elementAt(bit));
				}
				++bit;
				pow = (long)((ulong)pow >> 1);
			}

			GCMUtil.asBytes(y, output);
		}

		private void ensureAvailable(int bit)
		{
			int count = lookupPowX2.size();
			if (count <= bit)
			{
				long[] tmp = (long[])lookupPowX2.elementAt(count - 1);
				do
				{
					tmp = Arrays.clone(tmp);
					GCMUtil.square(tmp, tmp);
					lookupPowX2.addElement(tmp);
				} while (++count <= bit);
			}
		}
	}

}