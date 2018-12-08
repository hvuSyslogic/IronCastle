namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;

	public class PBESecretKeyFactory : BaseSecretKeyFactory, PBE
	{
		private bool forCipher;
		private int scheme;
		private int digest;
		private int keySize;
		private int ivSize;

		public PBESecretKeyFactory(string algorithm, ASN1ObjectIdentifier oid, bool forCipher, int scheme, int digest, int keySize, int ivSize) : base(algorithm, oid)
		{

			this.forCipher = forCipher;
			this.scheme = scheme;
			this.digest = digest;
			this.keySize = keySize;
			this.ivSize = ivSize;
		}

		public override SecretKey engineGenerateSecret(KeySpec keySpec)
		{
			if (keySpec is PBEKeySpec)
			{
				PBEKeySpec pbeSpec = (PBEKeySpec)keySpec;
				CipherParameters param;

				if (pbeSpec.getSalt() == null)
				{
					return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, null);
				}

				if (forCipher)
				{
					param = PBE_Util.makePBEParameters(pbeSpec, scheme, digest, keySize, ivSize);
				}
				else
				{
					param = PBE_Util.makePBEMacParameters(pbeSpec, scheme, digest, keySize);
				}

				return new BCPBEKey(this.algName, this.algOid, scheme, digest, keySize, ivSize, pbeSpec, param);
			}

			throw new InvalidKeySpecException("Invalid KeySpec");
		}
	}

}