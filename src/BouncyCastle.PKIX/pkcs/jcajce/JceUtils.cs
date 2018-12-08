using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.pkcs.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

	public class JceUtils
	{
		private static readonly Map PRFS = new HashMap();

		static JceUtils()
		{
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, "PBKDF2withHMACSHA1");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, "PBKDF2withHMACSHA256");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, "PBKDF2withHMACSHA512");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, "PBKDF2withHMACSHA224");
			PRFS.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, "PBKDF2withHMACSHA384");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, "PBKDF2withHMACSHA3-224");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, "PBKDF2withHMACSHA3-256");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, "PBKDF2withHMACSHA3-384");
			PRFS.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, "PBKDF2withHMACSHA3-512");
			PRFS.put(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, "PBKDF2withHMACGOST3411");
		}

		internal static string getAlgorithm(ASN1ObjectIdentifier algorithm)
		{
			if (!PRFS.containsKey(algorithm))
			{
				throw new IllegalStateException("no prf for algorithm: " + algorithm);
			}

			return ((string)PRFS.get(algorithm));
		}
	}

}