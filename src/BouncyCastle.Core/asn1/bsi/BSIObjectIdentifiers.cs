namespace org.bouncycastle.asn1.bsi
{

	/// <summary>
	/// See https://www.bsi.bund.de/cae/servlet/contentblob/471398/publicationFile/30615/BSI-TR-03111_pdf.pdf
	/// </summary>
	public interface BSIObjectIdentifiers
	{

		/* 0.4.0.127.0.7.1.1 */

		/* 0.4.0.127.0.7.1.1.4.1 */

		/* 0.4.0.127.0.7.1.1.4.1.1 */

		/* 0.4.0.127.0.7.1.1.4.1.2 */

		/* 0.4.0.127.0.7.1.1.4.1.3 */

		/* 0.4.0.127.0.7.1.1.4.1.4 */

		/* 0.4.0.127.0.7.1.1.4.1.5 */

		/* 0.4.0.127.0.7.1.1.4.1.6 */

		/// <summary>
		/// 0.4.0.127.0.7.1 </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963 OID: 0.4.0.127.0.7.1.1.5.1.1 </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963
		/// with hash function SHA-1
		/// OID: 0.4.0.127.0.7.1.1.5.1.1.1 
		/// </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963
		/// with hash function SHA224
		/// OID: 0.4.0.127.0.7.1.1.5.1.1.2 
		/// </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963
		/// with hash function SHA256
		/// OID: 0.4.0.127.0.7.1.1.5.1.1.3 
		/// </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963
		/// with hash function SHA384
		/// OID: 0.4.0.127.0.7.1.1.5.1.1.4 
		/// </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963
		/// with hash function SHA512
		/// OID: 0.4.0.127.0.7.1.1.5.1.1.5 
		/// </summary>

		/// <summary>
		/// ElGamal Elliptic Curve Key Agreement and Key Derivation according to X963
		/// with hash function RIPEMD160
		/// OID: 0.4.0.127.0.7.1.1.5.1.1.6 
		/// </summary>

		/// <summary>
		/// 	Key Derivation Function for Session Keys
		/// </summary>

		/// <summary>
		/// AES encryption (CBC) and authentication (CMAC)
		/// OID: 0.4.0.127.0.7.1.x 
		/// </summary>
		//TODO: replace "1" with correct OID
		//static final ASN1ObjectIdentifier aes_cbc_cmac = algorithm.branch("1");

		/// <summary>
		/// AES encryption (CBC) and authentication (CMAC) with 128 bit
		/// OID: 0.4.0.127.0.7.1.x.y1 
		/// </summary>
		//TODO:  replace "1" with correct OID
		//static final ASN1ObjectIdentifier id_aes128_CBC_CMAC = aes_cbc_cmac.branch("1");


		/// <summary>
		/// AES encryption (CBC) and authentication (CMAC) with 192 bit
		/// OID: 0.4.0.127.0.7.1.x.y2 
		/// </summary>
		//TODO:  replace "1" with correct OID
		//static final ASN1ObjectIdentifier id_aes192_CBC_CMAC = aes_cbc_cmac.branch("1");

		/// <summary>
		/// AES encryption (CBC) and authentication (CMAC) with 256 bit
		/// OID: 0.4.0.127.0.7.1.x.y3 
		/// </summary>
		//TODO:  replace "1" with correct OID
		//static final ASN1ObjectIdentifier id_aes256_CBC_CMAC = aes_cbc_cmac.branch("1");
	}

	public static class BSIObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier bsi_de = new ASN1ObjectIdentifier("0.4.0.127.0.7");
		public static readonly ASN1ObjectIdentifier id_ecc = bsi_de.branch("1.1");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_signatures = id_ecc.branch("4.1");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_SHA1 = ecdsa_plain_signatures.branch("1");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_SHA224 = ecdsa_plain_signatures.branch("2");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_SHA256 = ecdsa_plain_signatures.branch("3");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_SHA384 = ecdsa_plain_signatures.branch("4");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_SHA512 = ecdsa_plain_signatures.branch("5");
		public static readonly ASN1ObjectIdentifier ecdsa_plain_RIPEMD160 = ecdsa_plain_signatures.branch("6");
		public static readonly ASN1ObjectIdentifier algorithm = bsi_de.branch("1");
		public static readonly ASN1ObjectIdentifier ecka_eg = id_ecc.branch("5.1");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf = ecka_eg.branch("1");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf_SHA1 = ecka_eg_X963kdf.branch("1");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf_SHA224 = ecka_eg_X963kdf.branch("2");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf_SHA256 = ecka_eg_X963kdf.branch("3");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf_SHA384 = ecka_eg_X963kdf.branch("4");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf_SHA512 = ecka_eg_X963kdf.branch("5");
		public static readonly ASN1ObjectIdentifier ecka_eg_X963kdf_RIPEMD160 = ecka_eg_X963kdf.branch("6");
		public static readonly ASN1ObjectIdentifier ecka_eg_SessionKDF = ecka_eg.branch("2");
		public static readonly ASN1ObjectIdentifier ecka_eg_SessionKDF_3DES = ecka_eg_SessionKDF.branch("1");
		public static readonly ASN1ObjectIdentifier ecka_eg_SessionKDF_AES128 = ecka_eg_SessionKDF.branch("2");
		public static readonly ASN1ObjectIdentifier ecka_eg_SessionKDF_AES192 = ecka_eg_SessionKDF.branch("3");
		public static readonly ASN1ObjectIdentifier ecka_eg_SessionKDF_AES256 = ecka_eg_SessionKDF.branch("4");
	}

}