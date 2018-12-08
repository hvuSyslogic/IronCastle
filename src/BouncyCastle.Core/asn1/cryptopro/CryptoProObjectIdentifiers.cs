namespace org.bouncycastle.asn1.cryptopro
{

	/// <summary>
	/// <pre>
	/// GOST Algorithms OBJECT IDENTIFIERS :
	///    { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)}
	/// </pre>
	/// </summary>
	public interface CryptoProObjectIdentifiers
	{
		/// <summary>
		/// Base OID: 1.2.643.2.2 </summary>

		/// <summary>
		/// Gost R3411 OID: 1.2.643.2.2.9 </summary>
		/// <summary>
		/// Gost R3411 HMAC OID: 1.2.643.2.2.10 </summary>

		/// <summary>
		/// Gost R28147 OID: 1.2.643.2.2.21 </summary>

		/// <summary>
		/// Gost R28147-89-CryotoPro-A-ParamSet OID: 1.2.643.2.2.31.0 </summary>

		/// <summary>
		/// Gost R28147-89-CryotoPro-A-ParamSet OID: 1.2.643.2.2.31.1 </summary>

		/// <summary>
		/// Gost R28147-89-CryotoPro-B-ParamSet OID: 1.2.643.2.2.31.2 </summary>

		/// <summary>
		/// Gost R28147-89-CryotoPro-C-ParamSet OID: 1.2.643.2.2.31.3 </summary>

		/// <summary>
		/// Gost R28147-89-CryotoPro-D-ParamSet OID: 1.2.643.2.2.31.4 </summary>

		/// <summary>
		/// Gost R3410-94 OID: 1.2.643.2.2.20 </summary>
		/// <summary>
		/// Gost R3410-2001 OID: 1.2.643.2.2.19 </summary>

		/// <summary>
		/// Gost R3411-94-with-R3410-94 OID: 1.2.643.2.2.4 </summary>
		/// <summary>
		/// Gost R3411-94-with-R3410-2001 OID: 1.2.643.2.2.3 </summary>

		/// <summary>
		/// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) hashes(30) }
		/// <para>
		/// Gost R3411-94-CryptoProParamSet OID: 1.2.643.2.2.30.1
		/// </para>
		/// </summary>

		/// <summary>
		/// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) signs(32) }
		/// <para>
		/// Gost R3410-94-CryptoPro-A OID: 1.2.643.2.2.32.2
		/// </para>
		/// </summary>
		/// <summary>
		/// Gost R3410-94-CryptoPro-B OID: 1.2.643.2.2.32.3 </summary>
		/// <summary>
		/// Gost R3410-94-CryptoPro-C OID: 1.2.643.2.2.32.4 </summary>
		/// <summary>
		/// Gost R3410-94-CryptoPro-D OID: 1.2.643.2.2.32.5 </summary>

		/// <summary>
		/// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) exchanges(33) }
		/// <para>
		/// Gost R3410-94-CryptoPro-XchA OID: 1.2.643.2.2.33.1
		/// </para>
		/// </summary>
		/// <summary>
		/// Gost R3410-94-CryptoPro-XchB OID: 1.2.643.2.2.33.2 </summary>
		/// <summary>
		/// Gost R3410-94-CryptoPro-XchC OID: 1.2.643.2.2.33.3 </summary>

		/// <summary>
		/// { iso(1) member-body(2)ru(643) rans(2) cryptopro(2) ecc-signs(35) }
		/// <para>
		/// Gost R3410-2001-CryptoPro-A OID: 1.2.643.2.2.35.1
		/// </para>
		/// </summary>
		/// <summary>
		/// Gost R3410-2001-CryptoPro-B OID: 1.2.643.2.2.35.2 </summary>
		/// <summary>
		/// Gost R3410-2001-CryptoPro-C OID: 1.2.643.2.2.35.3 </summary>

		/// <summary>
		/// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) ecc-exchanges(36) }
		/// <para>
		/// Gost R3410-2001-CryptoPro-XchA OID: 1.2.643.2.2.36.0
		/// </para>
		/// </summary>
		/// <summary>
		/// Gost R3410-2001-CryptoPro-XchA OID: 1.2.643.2.2.36.1 </summary>

		/// <summary>
		/// Gost R3410-ElSqDH3410-default OID: 1.2.643.2.2.36.0 </summary>
		/// <summary>
		/// Gost R3410-ElSqDH3410-1 OID: 1.2.643.2.2.36.1 </summary>
	}

	public static class CryptoProObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier GOST_id = new ASN1ObjectIdentifier("1.2.643.2.2");
		public static readonly ASN1ObjectIdentifier gostR3411 = GOST_id.branch("9");
		public static readonly ASN1ObjectIdentifier gostR3411Hmac = GOST_id.branch("10");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_None_KeyWrap = GOST_id.branch("13.0");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_KeyWrap = GOST_id.branch("13.1");
		public static readonly ASN1ObjectIdentifier gostR28147_gcfb = GOST_id.branch("21");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_TestParamSet = GOST_id.branch("31.0");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_A_ParamSet = GOST_id.branch("31.1");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_B_ParamSet = GOST_id.branch("31.2");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_C_ParamSet = GOST_id.branch("31.3");
		public static readonly ASN1ObjectIdentifier id_Gost28147_89_CryptoPro_D_ParamSet = GOST_id.branch("31.4");
		public static readonly ASN1ObjectIdentifier gostR3410_94 = GOST_id.branch("20");
		public static readonly ASN1ObjectIdentifier gostR3410_2001 = GOST_id.branch("19");
		public static readonly ASN1ObjectIdentifier gostR3411_94_with_gostR3410_94 = GOST_id.branch("4");
		public static readonly ASN1ObjectIdentifier gostR3411_94_with_gostR3410_2001 = GOST_id.branch("3");
		public static readonly ASN1ObjectIdentifier gostR3411_94_CryptoProParamSet = GOST_id.branch("30.1");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_A = GOST_id.branch("32.2");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_B = GOST_id.branch("32.3");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_C = GOST_id.branch("32.4");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_D = GOST_id.branch("32.5");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_XchA = GOST_id.branch("33.1");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_XchB = GOST_id.branch("33.2");
		public static readonly ASN1ObjectIdentifier gostR3410_94_CryptoPro_XchC = GOST_id.branch("33.3");
		public static readonly ASN1ObjectIdentifier gostR3410_2001_CryptoPro_A = GOST_id.branch("35.1");
		public static readonly ASN1ObjectIdentifier gostR3410_2001_CryptoPro_B = GOST_id.branch("35.2");
		public static readonly ASN1ObjectIdentifier gostR3410_2001_CryptoPro_C = GOST_id.branch("35.3");
		public static readonly ASN1ObjectIdentifier gostR3410_2001_CryptoPro_XchA = GOST_id.branch("36.0");
		public static readonly ASN1ObjectIdentifier gostR3410_2001_CryptoPro_XchB = GOST_id.branch("36.1");
		public static readonly ASN1ObjectIdentifier gost_ElSgDH3410_default = GOST_id.branch("36.0");
		public static readonly ASN1ObjectIdentifier gost_ElSgDH3410_1 = GOST_id.branch("36.1");
		public static readonly ASN1ObjectIdentifier gostR3410_2001_CryptoPro_ESDH = GOST_id.branch("96");
		public static readonly ASN1ObjectIdentifier gostR3410_2001DH = GOST_id.branch("98");
	}

}