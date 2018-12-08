namespace org.bouncycastle.bcpg
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// base class for an ECDSA Public Key.
	/// </summary>
	public class ECDSAPublicBCPGKey : ECPublicBCPGKey
	{
		/// <param name="in"> the stream to read the packet from. </param>
		public ECDSAPublicBCPGKey(BCPGInputStream @in) : base(@in)
		{
		}

		public ECDSAPublicBCPGKey(ASN1ObjectIdentifier oid, ECPoint point) : base(oid, point)
		{
		}

		public ECDSAPublicBCPGKey(ASN1ObjectIdentifier oid, BigInteger encodedPoint) : base(oid, encodedPoint)
		{
		}

	}

}