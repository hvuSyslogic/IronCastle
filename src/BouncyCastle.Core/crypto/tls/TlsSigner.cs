namespace org.bouncycastle.crypto.tls
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public interface TlsSigner
	{
		void init(TlsContext context);

		byte[] generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1);

		byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey, byte[] hash);

		bool verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1);

		bool verifyRawSignature(SignatureAndHashAlgorithm algorithm, byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] hash);

		Signer createSigner(AsymmetricKeyParameter privateKey);

		Signer createSigner(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey);

		Signer createVerifyer(AsymmetricKeyParameter publicKey);

		Signer createVerifyer(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter publicKey);

		bool isValidPublicKey(AsymmetricKeyParameter publicKey);
	}

}