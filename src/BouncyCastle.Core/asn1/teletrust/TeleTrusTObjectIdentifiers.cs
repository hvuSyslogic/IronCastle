namespace org.bouncycastle.asn1.teletrust
{

	/// <summary>
	/// Object identifiers based on the TeleTrust branch.
	/// <pre>
	/// TeleTrusT:
	///   { iso(1) identifier-organization(3) teleTrust(36) algorithm(3)
	/// </pre>
	/// </summary>
	public interface TeleTrusTObjectIdentifiers
	{
		/// <summary>
		/// 1.3.36.3 </summary>

		/// <summary>
		/// 1.3.36.3.2.1 </summary>
		/// <summary>
		/// 1.3.36.3.2.2 </summary>
		/// <summary>
		/// 1.3.36.3.2.3 </summary>

		/// <summary>
		/// 1.3.36.3.3.1 </summary>

		/// <summary>
		/// 1.3.36.3.3.1.2 </summary>
		/// <summary>
		/// 1.3.36.3.3.1.3 </summary>
		/// <summary>
		/// 1.3.36.3.3.1.4 </summary>

		/// <summary>
		/// 1.3.36.3.3.2 </summary>

		/// <summary>
		/// 1.3.36.3.3.2,1 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.2 </summary>

		/// <summary>
		/// 1.3.36.3.3.2.8 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1 </summary>

		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.1 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.2 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.3 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.4 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.5 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.6 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.7 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.8 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.9 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.10 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.11 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.12 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.13 </summary>
		/// <summary>
		/// 1.3.36.3.3.2.8.1.1.14 </summary>
	}

	public static class TeleTrusTObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier teleTrusTAlgorithm = new ASN1ObjectIdentifier("1.3.36.3");
		public static readonly ASN1ObjectIdentifier ripemd160 = teleTrusTAlgorithm.branch("2.1");
		public static readonly ASN1ObjectIdentifier ripemd128 = teleTrusTAlgorithm.branch("2.2");
		public static readonly ASN1ObjectIdentifier ripemd256 = teleTrusTAlgorithm.branch("2.3");
		public static readonly ASN1ObjectIdentifier teleTrusTRSAsignatureAlgorithm = teleTrusTAlgorithm.branch("3.1");
		public static readonly ASN1ObjectIdentifier rsaSignatureWithripemd160 = teleTrusTRSAsignatureAlgorithm.branch("2");
		public static readonly ASN1ObjectIdentifier rsaSignatureWithripemd128 = teleTrusTRSAsignatureAlgorithm.branch("3");
		public static readonly ASN1ObjectIdentifier rsaSignatureWithripemd256 = teleTrusTRSAsignatureAlgorithm.branch("4");
		public static readonly ASN1ObjectIdentifier ecSign = teleTrusTAlgorithm.branch("3.2");
		public static readonly ASN1ObjectIdentifier ecSignWithSha1 = ecSign.branch("1");
		public static readonly ASN1ObjectIdentifier ecSignWithRipemd160 = ecSign.branch("2");
		public static readonly ASN1ObjectIdentifier ecc_brainpool = teleTrusTAlgorithm.branch("3.2.8");
		public static readonly ASN1ObjectIdentifier ellipticCurve = ecc_brainpool.branch("1");
		public static readonly ASN1ObjectIdentifier versionOne = ellipticCurve.branch("1");
		public static readonly ASN1ObjectIdentifier brainpoolP160r1 = versionOne.branch("1");
		public static readonly ASN1ObjectIdentifier brainpoolP160t1 = versionOne.branch("2");
		public static readonly ASN1ObjectIdentifier brainpoolP192r1 = versionOne.branch("3");
		public static readonly ASN1ObjectIdentifier brainpoolP192t1 = versionOne.branch("4");
		public static readonly ASN1ObjectIdentifier brainpoolP224r1 = versionOne.branch("5");
		public static readonly ASN1ObjectIdentifier brainpoolP224t1 = versionOne.branch("6");
		public static readonly ASN1ObjectIdentifier brainpoolP256r1 = versionOne.branch("7");
		public static readonly ASN1ObjectIdentifier brainpoolP256t1 = versionOne.branch("8");
		public static readonly ASN1ObjectIdentifier brainpoolP320r1 = versionOne.branch("9");
		public static readonly ASN1ObjectIdentifier brainpoolP320t1 = versionOne.branch("10");
		public static readonly ASN1ObjectIdentifier brainpoolP384r1 = versionOne.branch("11");
		public static readonly ASN1ObjectIdentifier brainpoolP384t1 = versionOne.branch("12");
		public static readonly ASN1ObjectIdentifier brainpoolP512r1 = versionOne.branch("13");
		public static readonly ASN1ObjectIdentifier brainpoolP512t1 = versionOne.branch("14");
	}

}