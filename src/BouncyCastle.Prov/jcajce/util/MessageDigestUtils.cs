using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.iso;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.gnu;
using org.bouncycastle.asn1.gm;

namespace org.bouncycastle.jcajce.util
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GMObjectIdentifiers = org.bouncycastle.asn1.gm.GMObjectIdentifiers;
	using GNUObjectIdentifiers = org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
	using ISOIECObjectIdentifiers = org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;

	public class MessageDigestUtils
	{
		private static Map<ASN1ObjectIdentifier, string> digestOidMap = new HashMap<ASN1ObjectIdentifier, string>();

		static MessageDigestUtils()
		{
			digestOidMap.put(PKCSObjectIdentifiers_Fields.md2, "MD2");
			digestOidMap.put(PKCSObjectIdentifiers_Fields.md4, "MD4");
			digestOidMap.put(PKCSObjectIdentifiers_Fields.md5, "MD5");
			digestOidMap.put(OIWObjectIdentifiers_Fields.idSHA1, "SHA-1");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha224, "SHA-224");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha256, "SHA-256");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha384, "SHA-384");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha512, "SHA-512");
			digestOidMap.put(TeleTrusTObjectIdentifiers_Fields.ripemd128, "RIPEMD-128");
			digestOidMap.put(TeleTrusTObjectIdentifiers_Fields.ripemd160, "RIPEMD-160");
			digestOidMap.put(TeleTrusTObjectIdentifiers_Fields.ripemd256, "RIPEMD-128");
			digestOidMap.put(ISOIECObjectIdentifiers_Fields.ripemd128, "RIPEMD-128");
			digestOidMap.put(ISOIECObjectIdentifiers_Fields.ripemd160, "RIPEMD-160");
			digestOidMap.put(CryptoProObjectIdentifiers_Fields.gostR3411, "GOST3411");
			digestOidMap.put(GNUObjectIdentifiers_Fields.Tiger_192, "Tiger");
			digestOidMap.put(ISOIECObjectIdentifiers_Fields.whirlpool, "Whirlpool");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha3_224, "SHA3-224");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha3_256, "SHA3-256");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha3_384, "SHA3-384");
			digestOidMap.put(NISTObjectIdentifiers_Fields.id_sha3_512, "SHA3-512");
			digestOidMap.put(GMObjectIdentifiers_Fields.sm3, "SM3");
		}

		/// <summary>
		/// Attempt to find a standard JCA name for the digest represented by the passed in OID.
		/// </summary>
		/// <param name="digestAlgOID"> the OID of the digest algorithm of interest. </param>
		/// <returns> a string representing the standard name - the OID as a string if none available. </returns>
		public static string getDigestName(ASN1ObjectIdentifier digestAlgOID)
		{
			string name = (string)digestOidMap.get(digestAlgOID); // for pre 1.5 JDK
			if (!string.ReferenceEquals(name, null))
			{
				return name;
			}

			return digestAlgOID.getId();
		}
	}

}