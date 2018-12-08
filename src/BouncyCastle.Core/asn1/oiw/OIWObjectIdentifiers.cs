namespace org.bouncycastle.asn1.oiw
{

	/// <summary>
	/// OIW organization's OIDs:
	/// <para>
	/// id-SHA1 OBJECT IDENTIFIER ::=    
	///   {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 }
	/// </para>
	/// </summary>
	public interface OIWObjectIdentifiers
	{
		/// <summary>
		/// OID: 1.3.14.3.2.2 </summary>
		/// <summary>
		/// OID: 1.3.14.3.2.3 </summary>
		/// <summary>
		/// OID: 1.3.14.3.2.4 </summary>

		/// <summary>
		/// OID: 1.3.14.3.2.6 </summary>
		/// <summary>
		/// OID: 1.3.14.3.2.7 </summary>
		/// <summary>
		/// OID: 1.3.14.3.2.8 </summary>
		/// <summary>
		/// OID: 1.3.14.3.2.9 </summary>

		/// <summary>
		/// OID: 1.3.14.3.2.17 </summary>

		/// <summary>
		/// OID: 1.3.14.3.2.26 </summary>

		/// <summary>
		/// OID: 1.3.14.3.2.27 </summary>

		/// <summary>
		/// OID: 1.3.14.3.2.29 </summary>

		/// <summary>
		/// <pre>
		/// ElGamal Algorithm OBJECT IDENTIFIER ::=    
		///   {iso(1) identified-organization(3) oiw(14) dirservsig(7) algorithm(2) encryption(1) 1 }
		/// </pre>
		/// OID: 1.3.14.7.2.1.1
		/// </summary>

	}

	public static class OIWObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier md4WithRSA = new ASN1ObjectIdentifier("1.3.14.3.2.2");
		public static readonly ASN1ObjectIdentifier md5WithRSA = new ASN1ObjectIdentifier("1.3.14.3.2.3");
		public static readonly ASN1ObjectIdentifier md4WithRSAEncryption = new ASN1ObjectIdentifier("1.3.14.3.2.4");
		public static readonly ASN1ObjectIdentifier desECB = new ASN1ObjectIdentifier("1.3.14.3.2.6");
		public static readonly ASN1ObjectIdentifier desCBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
		public static readonly ASN1ObjectIdentifier desOFB = new ASN1ObjectIdentifier("1.3.14.3.2.8");
		public static readonly ASN1ObjectIdentifier desCFB = new ASN1ObjectIdentifier("1.3.14.3.2.9");
		public static readonly ASN1ObjectIdentifier desEDE = new ASN1ObjectIdentifier("1.3.14.3.2.17");
		public static readonly ASN1ObjectIdentifier idSHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.26");
		public static readonly ASN1ObjectIdentifier dsaWithSHA1 = new ASN1ObjectIdentifier("1.3.14.3.2.27");
		public static readonly ASN1ObjectIdentifier sha1WithRSA = new ASN1ObjectIdentifier("1.3.14.3.2.29");
		public static readonly ASN1ObjectIdentifier elGamalAlgorithm = new ASN1ObjectIdentifier("1.3.14.7.2.1.1");
	}

}