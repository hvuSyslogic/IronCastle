using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.math.ec
{

	/// <summary>
	/// Class implementing the WTNAF (Window
	/// <code>&tau;</code>-adic Non-Adjacent Form) algorithm.
	/// </summary>
	public class WTauNafMultiplier : AbstractECMultiplier
	{
		// TODO Create WTauNafUtil class and move various functionality into it
		internal const string PRECOMP_NAME = "bc_wtnaf";

		/// <summary>
		/// Multiplies a <seealso cref="org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m"/>
		/// by <code>k</code> using the reduced <code>&tau;</code>-adic NAF (RTNAF)
		/// method. </summary>
		/// <param name="point"> The ECPoint.AbstractF2m to multiply. </param>
		/// <param name="k"> The integer by which to multiply <code>k</code>. </param>
		/// <returns> <code>p</code> multiplied by <code>k</code>. </returns>
		public override ECPoint multiplyPositive(ECPoint point, BigInteger k)
		{
			if (!(point is ECPoint.AbstractF2m))
			{
				throw new IllegalArgumentException("Only ECPoint.AbstractF2m can be " + "used in WTauNafMultiplier");
			}

			ECPoint.AbstractF2m p = (ECPoint.AbstractF2m)point;
			ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m)p.getCurve();
			int m = curve.getFieldSize();
			byte a = curve.getA().toBigInteger().byteValue();
			byte mu = Tnaf.getMu(a);
			BigInteger[] s = curve.getSi();

			ZTauElement rho = Tnaf.partModReduction(k, m, a, s, mu, (byte)10);

			return multiplyWTnaf(p, rho, a, mu);
		}

		/// <summary>
		/// Multiplies a <seealso cref="org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m"/>
		/// by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code> using
		/// the <code>&tau;</code>-adic NAF (TNAF) method. </summary>
		/// <param name="p"> The ECPoint.AbstractF2m to multiply. </param>
		/// <param name="lambda"> The element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code> of which to compute the
		/// <code>[&tau;]</code>-adic NAF. </param>
		/// <returns> <code>p</code> multiplied by <code>&lambda;</code>. </returns>
		private ECPoint.AbstractF2m multiplyWTnaf(ECPoint.AbstractF2m p, ZTauElement lambda, byte a, byte mu)
		{
			ZTauElement[] alpha = (a == 0) ? Tnaf.alpha0 : Tnaf.alpha1;

			BigInteger tw = Tnaf.getTw(mu, Tnaf.WIDTH);

			byte[] u = Tnaf.tauAdicWNaf(mu, lambda, Tnaf.WIDTH, BigInteger.valueOf(Tnaf.POW_2_WIDTH), tw, alpha);

			return multiplyFromWTnaf(p, u);
		}

		/// <summary>
		/// Multiplies a <seealso cref="org.bouncycastle.math.ec.ECPoint.AbstractF2m ECPoint.AbstractF2m"/>
		/// by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>
		/// using the window <code>&tau;</code>-adic NAF (TNAF) method, given the
		/// WTNAF of <code>&lambda;</code>. </summary>
		/// <param name="p"> The ECPoint.AbstractF2m to multiply. </param>
		/// <param name="u"> The the WTNAF of <code>&lambda;</code>.. </param>
		/// <returns> <code>&lambda; * p</code> </returns>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private static ECPoint.AbstractF2m multiplyFromWTnaf(final ECPoint.AbstractF2m p, byte[] u)
		private static ECPoint.AbstractF2m multiplyFromWTnaf(ECPoint.AbstractF2m p, byte[] u)
		{
			ECCurve.AbstractF2m curve = (ECCurve.AbstractF2m)p.getCurve();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte a = curve.getA().toBigInteger().byteValue();
			byte a = curve.getA().toBigInteger().byteValue();

			WTauNafPreCompInfo preCompInfo = (WTauNafPreCompInfo)curve.precompute(p, PRECOMP_NAME, new PreCompCallbackAnonymousInnerClass(p, a));

			ECPoint.AbstractF2m[] pu = preCompInfo.getPreComp();

			// TODO Include negations in precomp (optionally) and use from here
			ECPoint.AbstractF2m[] puNeg = new ECPoint.AbstractF2m[pu.Length];
			for (int i = 0; i < pu.Length; ++i)
			{
				puNeg[i] = (ECPoint.AbstractF2m)pu[i].negate();
			}


			// q = infinity
			ECPoint.AbstractF2m q = (ECPoint.AbstractF2m) p.getCurve().getInfinity();

			int tauCount = 0;
			for (int i = u.Length - 1; i >= 0; i--)
			{
				++tauCount;
				int ui = u[i];
				if (ui != 0)
				{
					q = q.tauPow(tauCount);
					tauCount = 0;

					ECPoint x = ui > 0 ? pu[(int)((uint)ui >> 1)] : puNeg[(int)((uint)(-ui) >> 1)];
					q = (ECPoint.AbstractF2m)q.add(x);
				}
			}
			if (tauCount > 0)
			{
				q = q.tauPow(tauCount);
			}
			return q;
		}

		public class PreCompCallbackAnonymousInnerClass : PreCompCallback
		{
			private ECPoint.AbstractF2m p;
			private byte a;

			public PreCompCallbackAnonymousInnerClass(ECPoint.AbstractF2m p, byte a)
			{
				this.p = p;
				this.a = a;
			}

			public PreCompInfo precompute(PreCompInfo existing)
			{
				if (existing is WTauNafPreCompInfo)
				{
					return existing;
				}

				WTauNafPreCompInfo result = new WTauNafPreCompInfo();
				result.setPreComp(Tnaf.getPreComp(p, a));
				return result;
			}
		}
	}

}