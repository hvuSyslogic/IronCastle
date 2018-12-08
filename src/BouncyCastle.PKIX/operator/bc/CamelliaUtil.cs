using org.bouncycastle.asn1.ntt;

namespace org.bouncycastle.@operator.bc
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NTTObjectIdentifiers = org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	public class CamelliaUtil
	{
		internal static AlgorithmIdentifier determineKeyEncAlg(KeyParameter key)
		{
			int length = key.getKey().Length * 8;
			ASN1ObjectIdentifier wrapOid;

			if (length == 128)
			{
				wrapOid = NTTObjectIdentifiers_Fields.id_camellia128_wrap;
			}
			else if (length == 192)
			{
				wrapOid = NTTObjectIdentifiers_Fields.id_camellia192_wrap;
			}
			else if (length == 256)
			{
				wrapOid = NTTObjectIdentifiers_Fields.id_camellia256_wrap;
			}
			else
			{
				throw new IllegalArgumentException("illegal keysize in Camellia");
			}

			return new AlgorithmIdentifier(wrapOid); // parameters must be
			// absent
		}
	}

}