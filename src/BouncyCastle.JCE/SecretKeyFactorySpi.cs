namespace javax.crypto
{

	/// <summary>
	/// This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
	/// for the <code>SecretKeyFactory</code> class.
	/// All the abstract methods in this class must be implemented by each 
	/// cryptographic service provider who wishes to supply the implementation
	/// of a secret-key factory for a particular algorithm.
	/// <para>
	/// A provider should document all the key specifications supported by its
	/// secret key factory.
	/// For example, the DES secret-key factory supplied by the "SunJCE" provider
	/// supports <code>DESKeySpec</code> as a transparent representation of DES
	/// keys, and that provider's secret-key factory for Triple DES keys supports
	/// <code>DESedeKeySpec</code> as a transparent representation of Triple DES
	/// keys.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SecretKey </seealso>
	/// <seealso cref= javax.crypto.spec.DESKeySpec </seealso>
	/// <seealso cref= javax.crypto.spec.DESedeKeySpec </seealso>
	public abstract class SecretKeyFactorySpi
	{
		public SecretKeyFactorySpi()
		{
		}

		/// <summary>
		/// Generates a <code>SecretKey</code> object from the
		/// provided key specification (key material).
		/// </summary>
		/// <param name="keySpec"> the specification (key material) of the secret key </param>
		/// <returns> the secret key </returns>
		/// <exception cref="InvalidKeySpecException"> if the given key specification
		/// is inappropriate for this secret-key factory to produce a secret key. </exception>
		public abstract SecretKey engineGenerateSecret(KeySpec keySpec);

		/// <summary>
		/// Returns a specification (key material) of the given key object in the requested format.
		/// </summary>
		/// <param name="key"> the key </param>
		/// <param name="keySpec"> the requested format in which the key material shall be returned </param>
		/// <returns> the underlying key specification (key material) in the requested format </returns>
		/// <exception cref="InvalidKeySpecException"> if the requested key specification is inappropriate for
		/// the given key (e.g., the algorithms associated with <code>key</code> and <code>keySpec</code> do
		/// not match, or <code>key</code> references a key on a cryptographic hardware device whereas
		/// <code>keySpec</code> is the specification of a software-based key), or the given key cannot be
		/// dealt with (e.g., the given key has an algorithm or format not supported by this secret-key factory). </exception>
		public abstract KeySpec engineGetKeySpec(SecretKey key, Class keySpec);

		/// <summary>
		/// Translates a key object, whose provider may be unknown or potentially untrusted, into a
		/// corresponding key object of this secret-key factory.
		/// </summary>
		/// <param name="key"> the key whose provider is unknown or untrusted </param>
		/// <returns> InvalidKeyException if the given key cannot be processed by this secret-key factory. </returns>
		public abstract SecretKey engineTranslateKey(SecretKey key);
	}

}