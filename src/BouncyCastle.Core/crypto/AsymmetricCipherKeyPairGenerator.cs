namespace org.bouncycastle.crypto
{
	/// <summary>
	/// interface that a public/private key pair generator should conform to.
	/// </summary>
	public interface AsymmetricCipherKeyPairGenerator
	{
		/// <summary>
		/// intialise the key pair generator.
		/// </summary>
		/// <param name="param"> the parameters the key pair is to be initialised with. </param>
		void init(KeyGenerationParameters param);

		/// <summary>
		/// return an AsymmetricCipherKeyPair containing the generated keys.
		/// </summary>
		/// <returns> an AsymmetricCipherKeyPair containing the generated keys. </returns>
		AsymmetricCipherKeyPair generateKeyPair();
	}


}