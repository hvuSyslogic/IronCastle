using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.@operator.bc
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	public class AESUtil
	{
		internal static AlgorithmIdentifier determineKeyEncAlg(KeyParameter key)
		{
			int length = key.getKey().Length * 8;
			ASN1ObjectIdentifier wrapOid;

			if (length == 128)
			{
				wrapOid = NISTObjectIdentifiers_Fields.id_aes128_wrap;
			}
			else if (length == 192)
			{
				wrapOid = NISTObjectIdentifiers_Fields.id_aes192_wrap;
			}
			else if (length == 256)
			{
				wrapOid = NISTObjectIdentifiers_Fields.id_aes256_wrap;
			}
			else
			{
				throw new IllegalArgumentException("illegal keysize in AES");
			}

			return new AlgorithmIdentifier(wrapOid); // parameters absent
		}
	}

}