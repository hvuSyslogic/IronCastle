namespace org.bouncycastle.jce
{

	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	/// <summary>
	/// Utility class for handling EC point decoding.
	/// </summary>
	public class ECPointUtil
	{
		/// <summary>
		/// Decode a point on this curve which has been encoded using point
		/// compression (X9.62 s 4.2.1 and 4.2.2) or regular encoding.
		/// </summary>
		/// <param name="curve">
		///            The elliptic curve. </param>
		/// <param name="encoded">
		///            The encoded point. </param>
		/// <returns> the decoded point. </returns>
		public static ECPoint decodePoint(EllipticCurve curve, byte[] encoded)
		{
			ECCurve c = null;

			if (curve.getField() is ECFieldFp)
			{
				c = new ECCurve.Fp(((ECFieldFp)curve.getField()).getP(), curve.getA(), curve.getB());
			}
			else
			{
				int[] k = ((ECFieldF2m)curve.getField()).getMidTermsOfReductionPolynomial();

				if (k.Length == 3)
				{
					c = new ECCurve.F2m(((ECFieldF2m)curve.getField()).getM(), k[2], k[1], k[0], curve.getA(), curve.getB());
				}
				else
				{
					c = new ECCurve.F2m(((ECFieldF2m)curve.getField()).getM(), k[0], curve.getA(), curve.getB());
				}
			}

			return EC5Util.convertPoint(c.decodePoint(encoded));
		}
	}

}