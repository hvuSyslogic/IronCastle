using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.@params
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class ECNamedDomainParameters : ECDomainParameters
	{
		private ASN1ObjectIdentifier name;

		public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n) : this(name, curve, G, n, org.bouncycastle.math.ec.ECConstants_Fields.ONE, null)
		{
		}

		public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h) : this(name, curve, G, n, h, null)
		{
		}

		public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed) : base(curve, G, n, h, seed)
		{

			this.name = name;
		}

		public virtual ASN1ObjectIdentifier getName()
		{
			return name;
		}
	}

}