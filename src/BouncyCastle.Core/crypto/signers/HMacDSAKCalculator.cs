using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.macs;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

				
	/// <summary>
	/// A deterministic K calculator based on the algorithm in section 3.2 of RFC 6979.
	/// </summary>
	public class HMacDSAKCalculator : DSAKCalculator
	{
		private static readonly BigInteger ZERO = BigInteger.valueOf(0);

		private readonly HMac hMac;
		private readonly byte[] K;
		private readonly byte[] V;

		private BigInteger n;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="digest"> digest to build the HMAC on. </param>
		public HMacDSAKCalculator(Digest digest)
		{
			this.hMac = new HMac(digest);
			this.V = new byte[hMac.getMacSize()];
			this.K = new byte[hMac.getMacSize()];
		}

		public virtual bool isDeterministic()
		{
			return true;
		}

		public virtual void init(BigInteger n, SecureRandom random)
		{
			throw new IllegalStateException("Operation not supported");
		}

		public virtual void init(BigInteger n, BigInteger d, byte[] message)
		{
			this.n = n;

			Arrays.fill(V, 0x01);
			Arrays.fill(K, 0);

			int size = BigIntegers.getUnsignedByteLength(n);
			byte[] x = new byte[size];
			byte[] dVal = BigIntegers.asUnsignedByteArray(d);

			JavaSystem.arraycopy(dVal, 0, x, x.Length - dVal.Length, dVal.Length);

			byte[] m = new byte[size];

			BigInteger mInt = bitsToInt(message);

			if (mInt.compareTo(n) >= 0)
			{
				mInt = mInt.subtract(n);
			}

			byte[] mVal = BigIntegers.asUnsignedByteArray(mInt);

			JavaSystem.arraycopy(mVal, 0, m, m.Length - mVal.Length, mVal.Length);

			hMac.init(new KeyParameter(K));

			hMac.update(V, 0, V.Length);
			hMac.update(0x00);
			hMac.update(x, 0, x.Length);
			hMac.update(m, 0, m.Length);

			hMac.doFinal(K, 0);

			hMac.init(new KeyParameter(K));

			hMac.update(V, 0, V.Length);

			hMac.doFinal(V, 0);

			hMac.update(V, 0, V.Length);
			hMac.update(0x01);
			hMac.update(x, 0, x.Length);
			hMac.update(m, 0, m.Length);

			hMac.doFinal(K, 0);

			hMac.init(new KeyParameter(K));

			hMac.update(V, 0, V.Length);

			hMac.doFinal(V, 0);
		}

		public virtual BigInteger nextK()
		{
			byte[] t = new byte[BigIntegers.getUnsignedByteLength(n)];

			for (;;)
			{
				int tOff = 0;

				while (tOff < t.Length)
				{
					hMac.update(V, 0, V.Length);

					hMac.doFinal(V, 0);

					int len = Math.Min(t.Length - tOff, V.Length);
					JavaSystem.arraycopy(V, 0, t, tOff, len);
					tOff += len;
				}

				BigInteger k = bitsToInt(t);

				if (k.compareTo(ZERO) > 0 && k.compareTo(n) < 0)
				{
					return k;
				}

				hMac.update(V, 0, V.Length);
				hMac.update(0x00);

				hMac.doFinal(K, 0);

				hMac.init(new KeyParameter(K));

				hMac.update(V, 0, V.Length);

				hMac.doFinal(V, 0);
			}
		}

		private BigInteger bitsToInt(byte[] t)
		{
			BigInteger v = new BigInteger(1, t);

			if (t.Length * 8 > n.bitLength())
			{
				v = v.shiftRight(t.Length * 8 - n.bitLength());
			}

			return v;
		}
	}

}