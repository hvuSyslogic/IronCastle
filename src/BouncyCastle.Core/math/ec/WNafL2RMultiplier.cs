using System;
using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec
{

	/// <summary>
	/// Class implementing the WNAF (Window Non-Adjacent Form) multiplication
	/// algorithm.
	/// </summary>
	public class WNafL2RMultiplier : AbstractECMultiplier
	{
		/// <summary>
		/// Multiplies <code>this</code> by an integer <code>k</code> using the
		/// Window NAF method. </summary>
		/// <param name="k"> The integer by which <code>this</code> is multiplied. </param>
		/// <returns> A new <code>ECPoint</code> which equals <code>this</code>
		/// multiplied by <code>k</code>. </returns>
		public override ECPoint multiplyPositive(ECPoint p, BigInteger k)
		{
			// Clamp the window width in the range [2, 16]
			int width = Math.Max(2, Math.Min(16, getWindowSize(k.bitLength())));

			WNafPreCompInfo wnafPreCompInfo = WNafUtil.precompute(p, width, true);
			ECPoint[] preComp = wnafPreCompInfo.getPreComp();
			ECPoint[] preCompNeg = wnafPreCompInfo.getPreCompNeg();

			int[] wnaf = WNafUtil.generateCompactWindowNaf(width, k);

			ECPoint R = p.getCurve().getInfinity();

			int i = wnaf.Length;

			/*
			 * NOTE: We try to optimize the first window using the precomputed points to substitute an
			 * addition for 2 or more doublings.
			 */
			if (i > 1)
			{
				int wi = wnaf[--i];
				int digit = wi >> 16, zeroes = wi & 0xFFFF;

				int n = Math.Abs(digit);
				ECPoint[] table = digit < 0 ? preCompNeg : preComp;

				// Optimization can only be used for values in the lower half of the table
				if ((n << 2) < (1 << width))
				{
					int highest = LongArray.bitLengths[n];

					// TODO Get addition/doubling cost ratio from curve and compare to 'scale' to see if worth substituting?
					int scale = width - highest;
					int lowBits = n ^ (1 << (highest - 1));

					int i1 = ((1 << (width - 1)) - 1);
					int i2 = (lowBits << scale) + 1;
					R = table[(int)((uint)i1 >> 1)].add(table[(int)((uint)i2 >> 1)]);

					zeroes -= scale;

	//              JavaSystem.@out.println("Optimized: 2^" + scale + " * " + n + " = " + i1 + " + " + i2);
				}
				else
				{
					R = table[(int)((uint)n >> 1)];
				}

				R = R.timesPow2(zeroes);
			}

			while (i > 0)
			{
				int wi = wnaf[--i];
				int digit = wi >> 16, zeroes = wi & 0xFFFF;

				int n = Math.Abs(digit);
				ECPoint[] table = digit < 0 ? preCompNeg : preComp;
				ECPoint r = table[(int)((uint)n >> 1)];

				R = R.twicePlus(r);
				R = R.timesPow2(zeroes);
			}

			return R;
		}

		/// <summary>
		/// Determine window width to use for a scalar multiplication of the given size.
		/// </summary>
		/// <param name="bits"> the bit-length of the scalar to multiply by </param>
		/// <returns> the window size to use </returns>
		public virtual int getWindowSize(int bits)
		{
			return WNafUtil.getWindowSize(bits);
		}
	}

}