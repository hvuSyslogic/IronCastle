namespace org.bouncycastle.crypto.tls
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public abstract class AbstractTlsSigner : TlsSigner
	{
		public abstract bool isValidPublicKey(AsymmetricKeyParameter publicKey);
		public abstract Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey);
		public abstract Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey);
		public abstract bool verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] hash);
		public abstract byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey, byte[] hash);
		protected internal TlsContext context;

		public virtual void init(TlsContext context)
		{
			this.context = context;
		}

		public virtual byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)
		{
			return generateRawSignature(null, privateKey, md5AndSha1);
		}

		public virtual bool verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)
		{
			return verifyRawSignature(null, sigBytes, publicKey, md5AndSha1);
		}

		public virtual Signer createSigner(AsymmetricKeyParameter privateKey)
		{
			return createSigner(null, privateKey);
		}

		public virtual Signer createVerifyer(AsymmetricKeyParameter publicKey)
		{
			return createVerifyer(null, publicKey);
		}
	}

}