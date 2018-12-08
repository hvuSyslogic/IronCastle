using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.asn1.sec
{
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

	/// <summary>
	/// Certicom object identifiers
	/// <pre>
	///  ellipticCurve OBJECT IDENTIFIER ::= {
	///        iso(1) identified-organization(3) certicom(132) curve(0)
	///  }
	///  secg-scheme OBJECT IDENTIFIER ::= {
	///     iso(1) identified-organization(3) certicom(132) schemes(1) }
	/// </pre>
	/// </summary>
	public interface SECObjectIdentifiers
	{
		/// <summary>
		/// Base OID: 1.3.132.0 </summary>

		/// <summary>
		///  sect163k1 OID: 1.3.132.0.1 </summary>
		/// <summary>
		///  sect163r1 OID: 1.3.132.0.2 </summary>
		/// <summary>
		///  sect239k1 OID: 1.3.132.0.3 </summary>
		/// <summary>
		///  sect113r1 OID: 1.3.132.0.4 </summary>
		/// <summary>
		///  sect113r2 OID: 1.3.132.0.5 </summary>
		/// <summary>
		///  secp112r1 OID: 1.3.132.0.6 </summary>
		/// <summary>
		///  secp112r2 OID: 1.3.132.0.7 </summary>
		/// <summary>
		///  secp160r1 OID: 1.3.132.0.8 </summary>
		/// <summary>
		///  secp160k1 OID: 1.3.132.0.9 </summary>
		/// <summary>
		///  secp256k1 OID: 1.3.132.0.10 </summary>
		/// <summary>
		///  sect163r2 OID: 1.3.132.0.15 </summary>
		/// <summary>
		///  sect283k1 OID: 1.3.132.0.16 </summary>
		/// <summary>
		///  sect283r1 OID: 1.3.132.0.17 </summary>
		/// <summary>
		///  sect131r1 OID: 1.3.132.0.22 </summary>
		/// <summary>
		///  sect131r2 OID: 1.3.132.0.23 </summary>
		/// <summary>
		///  sect193r1 OID: 1.3.132.0.24 </summary>
		/// <summary>
		///  sect193r2 OID: 1.3.132.0.25 </summary>
		/// <summary>
		///  sect233k1 OID: 1.3.132.0.26 </summary>
		/// <summary>
		///  sect233r1 OID: 1.3.132.0.27 </summary>
		/// <summary>
		///  secp128r1 OID: 1.3.132.0.28 </summary>
		/// <summary>
		///  secp128r2 OID: 1.3.132.0.29 </summary>
		/// <summary>
		///  secp160r2 OID: 1.3.132.0.30 </summary>
		/// <summary>
		///  secp192k1 OID: 1.3.132.0.31 </summary>
		/// <summary>
		///  secp224k1 OID: 1.3.132.0.32 </summary>
		/// <summary>
		///  secp224r1 OID: 1.3.132.0.33 </summary>
		/// <summary>
		///  secp384r1 OID: 1.3.132.0.34 </summary>
		/// <summary>
		///  secp521r1 OID: 1.3.132.0.35 </summary>
		/// <summary>
		///  sect409k1 OID: 1.3.132.0.36 </summary>
		/// <summary>
		///  sect409r1 OID: 1.3.132.0.37 </summary>
		/// <summary>
		///  sect571k1 OID: 1.3.132.0.38 </summary>
		/// <summary>
		///  sect571r1 OID: 1.3.132.0.39 </summary>

		/// <summary>
		///  secp192r1 OID: 1.3.132.0.prime192v1 </summary>
		/// <summary>
		///  secp256r1 OID: 1.3.132.0.prime256v1 </summary>
	}

	public static class SECObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier ellipticCurve = new ASN1ObjectIdentifier("1.3.132.0");
		public static readonly ASN1ObjectIdentifier sect163k1 = ellipticCurve.branch("1");
		public static readonly ASN1ObjectIdentifier sect163r1 = ellipticCurve.branch("2");
		public static readonly ASN1ObjectIdentifier sect239k1 = ellipticCurve.branch("3");
		public static readonly ASN1ObjectIdentifier sect113r1 = ellipticCurve.branch("4");
		public static readonly ASN1ObjectIdentifier sect113r2 = ellipticCurve.branch("5");
		public static readonly ASN1ObjectIdentifier secp112r1 = ellipticCurve.branch("6");
		public static readonly ASN1ObjectIdentifier secp112r2 = ellipticCurve.branch("7");
		public static readonly ASN1ObjectIdentifier secp160r1 = ellipticCurve.branch("8");
		public static readonly ASN1ObjectIdentifier secp160k1 = ellipticCurve.branch("9");
		public static readonly ASN1ObjectIdentifier secp256k1 = ellipticCurve.branch("10");
		public static readonly ASN1ObjectIdentifier sect163r2 = ellipticCurve.branch("15");
		public static readonly ASN1ObjectIdentifier sect283k1 = ellipticCurve.branch("16");
		public static readonly ASN1ObjectIdentifier sect283r1 = ellipticCurve.branch("17");
		public static readonly ASN1ObjectIdentifier sect131r1 = ellipticCurve.branch("22");
		public static readonly ASN1ObjectIdentifier sect131r2 = ellipticCurve.branch("23");
		public static readonly ASN1ObjectIdentifier sect193r1 = ellipticCurve.branch("24");
		public static readonly ASN1ObjectIdentifier sect193r2 = ellipticCurve.branch("25");
		public static readonly ASN1ObjectIdentifier sect233k1 = ellipticCurve.branch("26");
		public static readonly ASN1ObjectIdentifier sect233r1 = ellipticCurve.branch("27");
		public static readonly ASN1ObjectIdentifier secp128r1 = ellipticCurve.branch("28");
		public static readonly ASN1ObjectIdentifier secp128r2 = ellipticCurve.branch("29");
		public static readonly ASN1ObjectIdentifier secp160r2 = ellipticCurve.branch("30");
		public static readonly ASN1ObjectIdentifier secp192k1 = ellipticCurve.branch("31");
		public static readonly ASN1ObjectIdentifier secp224k1 = ellipticCurve.branch("32");
		public static readonly ASN1ObjectIdentifier secp224r1 = ellipticCurve.branch("33");
		public static readonly ASN1ObjectIdentifier secp384r1 = ellipticCurve.branch("34");
		public static readonly ASN1ObjectIdentifier secp521r1 = ellipticCurve.branch("35");
		public static readonly ASN1ObjectIdentifier sect409k1 = ellipticCurve.branch("36");
		public static readonly ASN1ObjectIdentifier sect409r1 = ellipticCurve.branch("37");
		public static readonly ASN1ObjectIdentifier sect571k1 = ellipticCurve.branch("38");
		public static readonly ASN1ObjectIdentifier sect571r1 = ellipticCurve.branch("39");
		public static readonly ASN1ObjectIdentifier secp192r1 = X9ObjectIdentifiers_Fields.prime192v1;
		public static readonly ASN1ObjectIdentifier secp256r1 = X9ObjectIdentifiers_Fields.prime256v1;
		public static readonly ASN1ObjectIdentifier secg_scheme = new ASN1ObjectIdentifier("1.3.132.1");
		public static readonly ASN1ObjectIdentifier dhSinglePass_stdDH_sha224kdf_scheme = secg_scheme.branch("11.0");
		public static readonly ASN1ObjectIdentifier dhSinglePass_stdDH_sha256kdf_scheme = secg_scheme.branch("11.1");
		public static readonly ASN1ObjectIdentifier dhSinglePass_stdDH_sha384kdf_scheme = secg_scheme.branch("11.2");
		public static readonly ASN1ObjectIdentifier dhSinglePass_stdDH_sha512kdf_scheme = secg_scheme.branch("11.3");
		public static readonly ASN1ObjectIdentifier dhSinglePass_cofactorDH_sha224kdf_scheme = secg_scheme.branch("14.0");
		public static readonly ASN1ObjectIdentifier dhSinglePass_cofactorDH_sha256kdf_scheme = secg_scheme.branch("14.1");
		public static readonly ASN1ObjectIdentifier dhSinglePass_cofactorDH_sha384kdf_scheme = secg_scheme.branch("14.2");
		public static readonly ASN1ObjectIdentifier dhSinglePass_cofactorDH_sha512kdf_scheme = secg_scheme.branch("14.3");
		public static readonly ASN1ObjectIdentifier mqvSinglePass_sha224kdf_scheme = secg_scheme.branch("15.0");
		public static readonly ASN1ObjectIdentifier mqvSinglePass_sha256kdf_scheme = secg_scheme.branch("15.1");
		public static readonly ASN1ObjectIdentifier mqvSinglePass_sha384kdf_scheme = secg_scheme.branch("15.2");
		public static readonly ASN1ObjectIdentifier mqvSinglePass_sha512kdf_scheme = secg_scheme.branch("15.3");
		public static readonly ASN1ObjectIdentifier mqvFull_sha224kdf_scheme = secg_scheme.branch("16.0");
		public static readonly ASN1ObjectIdentifier mqvFull_sha256kdf_scheme = secg_scheme.branch("16.1");
		public static readonly ASN1ObjectIdentifier mqvFull_sha384kdf_scheme = secg_scheme.branch("16.2");
		public static readonly ASN1ObjectIdentifier mqvFull_sha512kdf_scheme = secg_scheme.branch("16.3");
	}

}