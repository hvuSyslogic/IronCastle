using org.bouncycastle.openpgp;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// Basic utility class
	/// </summary>
	public class JcaJcePGPUtil
	{
		public static SecretKey makeSymmetricKey(int algorithm, byte[] keyBytes)
		{
			string algName = PGPUtil.getSymmetricCipherName(algorithm);

			if (string.ReferenceEquals(algName, null))
			{
				throw new PGPException("unknown symmetric algorithm: " + algorithm);
			}

			return new SecretKeySpec(keyBytes, algName);
		}

		internal static ECPoint decodePoint(BigInteger encodedPoint, ECCurve curve)
		{
			return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
		}

		internal static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
		{
			return ECNamedCurveTable.getByOID(curveOID);
		}
	}

}