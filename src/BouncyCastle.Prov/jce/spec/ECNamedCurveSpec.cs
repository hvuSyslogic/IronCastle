using org.bouncycastle.math.ec;

namespace org.bouncycastle.jce.spec
{

	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using FiniteField = org.bouncycastle.math.field.FiniteField;
	using Polynomial = org.bouncycastle.math.field.Polynomial;
	using PolynomialExtensionField = org.bouncycastle.math.field.PolynomialExtensionField;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// specification signifying that the curve parameters can also be
	/// referred to by name.
	/// </summary>
	public class ECNamedCurveSpec : java.security.spec.ECParameterSpec
	{
		private string name;

		private static EllipticCurve convertCurve(ECCurve curve, byte[] seed)
		{
			ECField field = convertField(curve.getField());
			BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();
			return new EllipticCurve(field, a, b, seed);
		}

		private static ECField convertField(FiniteField field)
		{
			if (ECAlgorithms.isFpField(field))
			{
				return new ECFieldFp(field.getCharacteristic());
			}
			else //if (ECAlgorithms.isF2mField(curveField))
			{
				Polynomial poly = ((PolynomialExtensionField)field).getMinimalPolynomial();
				int[] exponents = poly.getExponentsPresent();
				int[] ks = Arrays.reverse(Arrays.copyOfRange(exponents, 1, exponents.Length - 1));
				return new ECFieldF2m(poly.getDegree(), ks);
			}
		}

		public ECNamedCurveSpec(string name, ECCurve curve, ECPoint g, BigInteger n) : base(convertCurve(curve, null), EC5Util.convertPoint(g), n, 1)
		{

			this.name = name;
		}

		public ECNamedCurveSpec(string name, EllipticCurve curve, ECPoint g, BigInteger n) : base(curve, g, n, 1)
		{

			this.name = name;
		}

		public ECNamedCurveSpec(string name, ECCurve curve, ECPoint g, BigInteger n, BigInteger h) : base(convertCurve(curve, null), EC5Util.convertPoint(g), n, h.intValue())
		{

			this.name = name;
		}

		public ECNamedCurveSpec(string name, EllipticCurve curve, ECPoint g, BigInteger n, BigInteger h) : base(curve, g, n, h.intValue())
		{

			this.name = name;
		}

		public ECNamedCurveSpec(string name, ECCurve curve, ECPoint g, BigInteger n, BigInteger h, byte[] seed) : base(convertCurve(curve, seed), EC5Util.convertPoint(g), n, h.intValue())
		{

			this.name = name;
		}

		/// <summary>
		/// return the name of the curve the EC domain parameters belong to.
		/// </summary>
		public virtual string getName()
		{
			return name;
		}
	}

}