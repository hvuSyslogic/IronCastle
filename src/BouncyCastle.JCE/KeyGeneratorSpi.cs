namespace javax.crypto
{

	/// <summary>
	/// This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
	/// for the <code>KeyGenerator</code> class.
	/// All the abstract methods in this class must be implemented by each 
	/// cryptographic service provider who wishes to supply the implementation
	/// of a key generator for a particular algorithm.
	/// </summary>
	/// <seealso cref= SecretKey </seealso>
	public abstract class KeyGeneratorSpi
	{
		public KeyGeneratorSpi()
		{
		}

		/// <summary>
		/// Initializes the key generator.
		/// </summary>
		/// <param name="random"> the source of randomness for this generator </param>
		public abstract void engineInit(SecureRandom random);

		/// <summary>
		/// Initializes the key generator with the specified parameter
		/// set and a user-provided source of randomness.
		/// </summary>
		/// <param name="params"> the key generation parameters </param>
		/// <param name="random"> the source of randomness for this key generator </param>
		/// <exception cref="InvalidAlgorithmParameterException"> if <code>params</code> is
		/// inappropriate for this key generator </exception>
		public abstract void engineInit(AlgorithmParameterSpec @params, SecureRandom random);

		/// <summary>
		/// Initializes this key generator for a certain keysize, using the given
		/// source of randomness.
		/// </summary>
		/// <param name="keysize"> the keysize. This is an algorithm-specific metric, specified in number of bits. </param>
		/// <param name="random"> the source of randomness for this key generator. </param>
		/// <exception cref="InvalidParameterException"> if keysize is wrong or not supported. </exception>
		public abstract void engineInit(int keysize, SecureRandom random);

		/// <summary>
		/// Generates a secret key.
		/// </summary>
		/// <returns> the new key. </returns>
		public abstract SecretKey engineGenerateKey();
	}

}