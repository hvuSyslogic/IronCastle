using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.pkcs
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Integers = org.bouncycastle.util.Integers;

	public class PKCSUtils
	{
		private static readonly Map PRFS_SALT = new HashMap();

		static PKCSUtils()
		{
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, Integers.valueOf(20));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, Integers.valueOf(32));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, Integers.valueOf(64));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, Integers.valueOf(28));
			PRFS_SALT.put(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, Integers.valueOf(48));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_224, Integers.valueOf(28));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_256, Integers.valueOf(32));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_384, Integers.valueOf(48));
			PRFS_SALT.put(NISTObjectIdentifiers_Fields.id_hmacWithSHA3_512, Integers.valueOf(64));
			PRFS_SALT.put(CryptoProObjectIdentifiers_Fields.gostR3411Hmac, Integers.valueOf(32));
		}

		internal static int getSaltSize(ASN1ObjectIdentifier algorithm)
		{
			if (!PRFS_SALT.containsKey(algorithm))
			{
				throw new IllegalStateException("no salt size for algorithm: " + algorithm);
			}

			return ((int?)PRFS_SALT.get(algorithm)).Value;
		}
	}

}