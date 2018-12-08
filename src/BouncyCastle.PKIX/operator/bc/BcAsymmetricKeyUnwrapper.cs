using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.@operator.bc
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public abstract class BcAsymmetricKeyUnwrapper : AsymmetricKeyUnwrapper
	{
		private AsymmetricKeyParameter privateKey;

		public BcAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey) : base(encAlgId)
		{

			this.privateKey = privateKey;
		}

		public override GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
		{
			AsymmetricBlockCipher keyCipher = createAsymmetricUnwrapper(this.getAlgorithmIdentifier().getAlgorithm());

			keyCipher.init(false, privateKey);
			try
			{
				byte[] key = keyCipher.processBlock(encryptedKey, 0, encryptedKey.Length);

				if (encryptedKeyAlgorithm.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.des_EDE3_CBC))
				{
					return new GenericKey(encryptedKeyAlgorithm, key);
				}
				else
				{
					return new GenericKey(encryptedKeyAlgorithm, key);
				}
			}
			catch (InvalidCipherTextException e)
			{
				throw new OperatorException("unable to recover secret key: " + e.Message, e);
			}
		}

		public abstract AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm);
	}

}