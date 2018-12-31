using org.bouncycastle.asn1;
using org.bouncycastle.asn1.bc;

namespace org.bouncycastle.pqc.asn1
{
		
	/// <summary>
	/// PQC:
	/// <para>
	/// { iso(1) identifier-organization(3) dod(6) internet(1) private(4) 1 8301 3 1 3 5 3 ... }
	/// </para>
	/// </summary>
	public interface PQCObjectIdentifiers
	{
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.5.3.2 </summary>

		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.5.3.2.1 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.5.3.2.2 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.5.3.2.3 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.5.3.2.4 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.5.3.2.5 </summary>

		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.3 </summary>

		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.3.1 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.3.2 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.3.3 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.3.4 </summary>
		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.3.5 </summary>

		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.4.1 </summary>

		/// <summary>
		/// 1.3.6.1.4.1.8301.3.1.3.4.2 </summary>

		/// <summary>
		/// XMSS
		/// </summary>


		/// <summary>
		/// XMSS^MT
		/// </summary>

		// old OIDs.
		/// @deprecated use xmss_SHA256ph 
		/// @deprecated use xmss_SHA512ph 
		/// @deprecated use xmss_SHAKE128ph 
		/// @deprecated use xmss_SHAKE256ph 

		/// @deprecated use xmss_mt_SHA256ph 
		/// @deprecated use xmss_mt_SHA512ph 
		/// @deprecated use xmss_mt_SHAKE128ph 
		/// @deprecated use xmss_mt_SHAKE256ph 

		/// <summary>
		/// qTESLA
		/// </summary>
	}

	public static class PQCObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier rainbow = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.5.3.2");
		public static readonly ASN1ObjectIdentifier rainbowWithSha1 = rainbow.branch("1");
		public static readonly ASN1ObjectIdentifier rainbowWithSha224 = rainbow.branch("2");
		public static readonly ASN1ObjectIdentifier rainbowWithSha256 = rainbow.branch("3");
		public static readonly ASN1ObjectIdentifier rainbowWithSha384 = rainbow.branch("4");
		public static readonly ASN1ObjectIdentifier rainbowWithSha512 = rainbow.branch("5");
		public static readonly ASN1ObjectIdentifier gmss = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.3");
		public static readonly ASN1ObjectIdentifier gmssWithSha1 = gmss.branch("1");
		public static readonly ASN1ObjectIdentifier gmssWithSha224 = gmss.branch("2");
		public static readonly ASN1ObjectIdentifier gmssWithSha256 = gmss.branch("3");
		public static readonly ASN1ObjectIdentifier gmssWithSha384 = gmss.branch("4");
		public static readonly ASN1ObjectIdentifier gmssWithSha512 = gmss.branch("5");
		public static readonly ASN1ObjectIdentifier mcEliece = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");
		public static readonly ASN1ObjectIdentifier mcElieceCca2 = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");
		public static readonly ASN1ObjectIdentifier mcElieceFujisaki = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.1");
		public static readonly ASN1ObjectIdentifier mcEliecePointcheval = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.2");
		public static readonly ASN1ObjectIdentifier mcElieceKobara_Imai = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2.3");
		public static readonly ASN1ObjectIdentifier sphincs256 = BCObjectIdentifiers_Fields.sphincs256;
		public static readonly ASN1ObjectIdentifier sphincs256_with_BLAKE512 = BCObjectIdentifiers_Fields.sphincs256_with_BLAKE512;
		public static readonly ASN1ObjectIdentifier sphincs256_with_SHA512 = BCObjectIdentifiers_Fields.sphincs256_with_SHA512;
		public static readonly ASN1ObjectIdentifier sphincs256_with_SHA3_512 = BCObjectIdentifiers_Fields.sphincs256_with_SHA3_512;
		public static readonly ASN1ObjectIdentifier newHope = BCObjectIdentifiers_Fields.newHope;
		public static readonly ASN1ObjectIdentifier xmss = BCObjectIdentifiers_Fields.xmss;
		public static readonly ASN1ObjectIdentifier xmss_SHA256ph = BCObjectIdentifiers_Fields.xmss_SHA256ph;
		public static readonly ASN1ObjectIdentifier xmss_SHA512ph = BCObjectIdentifiers_Fields.xmss_SHA512ph;
		public static readonly ASN1ObjectIdentifier xmss_SHAKE128ph = BCObjectIdentifiers_Fields.xmss_SHAKE128ph;
		public static readonly ASN1ObjectIdentifier xmss_SHAKE256ph = BCObjectIdentifiers_Fields.xmss_SHAKE256ph;
		public static readonly ASN1ObjectIdentifier xmss_SHA256 = BCObjectIdentifiers_Fields.xmss_SHA256;
		public static readonly ASN1ObjectIdentifier xmss_SHA512 = BCObjectIdentifiers_Fields.xmss_SHA512;
		public static readonly ASN1ObjectIdentifier xmss_SHAKE128 = BCObjectIdentifiers_Fields.xmss_SHAKE128;
		public static readonly ASN1ObjectIdentifier xmss_SHAKE256 = BCObjectIdentifiers_Fields.xmss_SHAKE256;
		public static readonly ASN1ObjectIdentifier xmss_mt = BCObjectIdentifiers_Fields.xmss_mt;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHA256ph = BCObjectIdentifiers_Fields.xmss_mt_SHA256ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHA512ph = BCObjectIdentifiers_Fields.xmss_mt_SHA512ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHAKE128ph = BCObjectIdentifiers_Fields.xmss_mt_SHAKE128ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHAKE256ph = BCObjectIdentifiers_Fields.xmss_mt_SHAKE256ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHA256 = BCObjectIdentifiers_Fields.xmss_mt_SHA256;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHA512 = BCObjectIdentifiers_Fields.xmss_mt_SHA512;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHAKE128 = BCObjectIdentifiers_Fields.xmss_mt_SHAKE128;
		public static readonly ASN1ObjectIdentifier xmss_mt_SHAKE256 = BCObjectIdentifiers_Fields.xmss_mt_SHAKE256;
		public static readonly ASN1ObjectIdentifier xmss_with_SHA256 = xmss_SHA256ph;
		public static readonly ASN1ObjectIdentifier xmss_with_SHA512 = xmss_SHA512ph;
		public static readonly ASN1ObjectIdentifier xmss_with_SHAKE128 = xmss_SHAKE128ph;
		public static readonly ASN1ObjectIdentifier xmss_with_SHAKE256 = xmss_SHAKE256ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_with_SHA256 = xmss_mt_SHA256ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_with_SHA512 = xmss_mt_SHA512ph;
		public static readonly ASN1ObjectIdentifier xmss_mt_with_SHAKE128 = xmss_mt_SHAKE128;
		public static readonly ASN1ObjectIdentifier xmss_mt_with_SHAKE256 = xmss_mt_SHAKE256;
		public static readonly ASN1ObjectIdentifier qTESLA = BCObjectIdentifiers_Fields.qTESLA;
		public static readonly ASN1ObjectIdentifier qTESLA_I = BCObjectIdentifiers_Fields.qTESLA_I;
		public static readonly ASN1ObjectIdentifier qTESLA_III_size = BCObjectIdentifiers_Fields.qTESLA_III_size;
		public static readonly ASN1ObjectIdentifier qTESLA_III_speed = BCObjectIdentifiers_Fields.qTESLA_III_speed;
		public static readonly ASN1ObjectIdentifier qTESLA_p_I = BCObjectIdentifiers_Fields.qTESLA_p_I;
		public static readonly ASN1ObjectIdentifier qTESLA_p_III = BCObjectIdentifiers_Fields.qTESLA_p_III;
	}

}