namespace org.bouncycastle.bcpg
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// base class for an EdDSA Public Key.
	/// </summary>
	public class EdDSAPublicBCPGKey : ECPublicBCPGKey
	{
		/// <param name="in"> the stream to read the packet from. </param>
		public EdDSAPublicBCPGKey(BCPGInputStream @in) : base(@in)
		{
		}

		public EdDSAPublicBCPGKey(ASN1ObjectIdentifier oid, ECPoint point) : base(oid, point)
		{
		}

		public EdDSAPublicBCPGKey(ASN1ObjectIdentifier oid, BigInteger encodedPoint) : base(oid, encodedPoint)
		{
		}

	}

}