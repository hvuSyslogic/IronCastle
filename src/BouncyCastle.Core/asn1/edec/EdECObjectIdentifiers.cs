namespace org.bouncycastle.asn1.edec
{

	/// <summary>
	/// Edwards Elliptic Curve Object Identifiers (RFC 8410)
	/// </summary>
	public interface EdECObjectIdentifiers
	{
	}

	public static class EdECObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_edwards_curve_algs = new ASN1ObjectIdentifier("1.3.101");
		public static readonly ASN1ObjectIdentifier id_X25519 = id_edwards_curve_algs.branch("110").intern();
		public static readonly ASN1ObjectIdentifier id_X448 = id_edwards_curve_algs.branch("111").intern();
		public static readonly ASN1ObjectIdentifier id_Ed25519 = id_edwards_curve_algs.branch("112").intern();
		public static readonly ASN1ObjectIdentifier id_Ed448 = id_edwards_curve_algs.branch("113").intern();
	}

}