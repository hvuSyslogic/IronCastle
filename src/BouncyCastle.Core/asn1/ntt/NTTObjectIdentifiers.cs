namespace org.bouncycastle.asn1.ntt
{

	/// <summary>
	/// From <a href="http://tools.ietf.org/html/rfc3657">RFC 3657</a>
	/// Use of the Camellia Encryption Algorithm
	/// in Cryptographic Message Syntax (CMS)
	/// </summary>
	public interface NTTObjectIdentifiers
	{
		/// <summary>
		/// id-camellia128-cbc; OID 1.2.392.200011.61.1.1.1.2 </summary>
		/// <summary>
		/// id-camellia192-cbc; OID 1.2.392.200011.61.1.1.1.3 </summary>
		/// <summary>
		/// id-camellia256-cbc; OID 1.2.392.200011.61.1.1.1.4 </summary>

		/// <summary>
		/// id-camellia128-wrap; OID 1.2.392.200011.61.1.1.3.2 </summary>
		/// <summary>
		/// id-camellia192-wrap; OID 1.2.392.200011.61.1.1.3.3 </summary>
		/// <summary>
		/// id-camellia256-wrap; OID 1.2.392.200011.61.1.1.3.4 </summary>
	}

	public static class NTTObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_camellia128_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.2");
		public static readonly ASN1ObjectIdentifier id_camellia192_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.3");
		public static readonly ASN1ObjectIdentifier id_camellia256_cbc = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.1.4");
		public static readonly ASN1ObjectIdentifier id_camellia128_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.2");
		public static readonly ASN1ObjectIdentifier id_camellia192_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.3");
		public static readonly ASN1ObjectIdentifier id_camellia256_wrap = new ASN1ObjectIdentifier("1.2.392.200011.61.1.1.3.4");
	}

}