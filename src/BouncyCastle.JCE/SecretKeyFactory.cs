namespace javax.crypto
{

	/// <summary>
	/// This class represents a factory for secret keys.
	/// 
	/// <para>
	/// Key factories are used to convert <I>keys</I> (opaque
	/// cryptographic keys of type <code>Key</code>) into <I>key specifications</I>
	/// (transparent representations of the underlying key material), and vice versa.
	/// Secret key factories operate only on secret (symmetric) keys.
	/// </para>
	/// <para>
	/// Key factories are bi-directional, i.e., they allow to build an opaque
	/// key object from a given key specification (key material), or to retrieve
	/// the underlying key material of a key object in a suitable format.
	/// </para>
	/// <para>
	/// Application developers should refer to their provider's documentation
	/// to find out which key specifications are supported by the
	/// <a href="#generateSecret(java.security.spec.KeySpec)">generateSecret</a> and
	/// <a href="#getKeySpec(javax.crypto.SecretKey, java.lang.Class)">getKeySpec</a> methods.
	/// For example, the DES secret-key factory supplied by the "SunJCE" provider
	/// supports <code>DESKeySpec</code> as a transparent representation of DES
	/// keys, and that provider's secret-key factory for Triple DES keys supports
	/// <code>DESedeKeySpec</code> as a transparent representation of Triple DES keys.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SecretKey </seealso>
	/// <seealso cref= javax.crypto.spec.DESKeySpec </seealso>
	/// <seealso cref= javax.crypto.spec.DESedeKeySpec </seealso>
	/// <seealso cref= javax.crypto.spec.PBEKeySpec </seealso>
	public class SecretKeyFactory
	{
		internal SecretKeyFactorySpi keyFacSpi;
		internal Provider provider;
		internal string algorithm;

		/// <summary>
		/// Creates a SecretKeyFactory object.
		/// </summary>
		/// <param name="keyFacSpi"> the delegate </param>
		/// <param name="provider"> the provider </param>
		/// <param name="algorithm"> the secret-key algorithm </param>
		public SecretKeyFactory(SecretKeyFactorySpi keyFacSpi, Provider provider, string algorithm)
		{
			this.keyFacSpi = keyFacSpi;
			this.provider = provider;
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Generates a <code>SecretKeyFactory</code> object for the specified secret-key algorithm.
		/// If the default provider package provides an implementation of the
		/// requested factory, an instance of <code>SecretKeyFactory</code>
		/// containing that implementation is returned.
		/// If the requested factory is not available in the default provider
		/// package, other provider packages are searched.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested secret-key algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference </a> 
		/// for information about standard algorithm names. </param>
		/// <returns> a <code>SecretKeyFactory</code> object for the specified secret-key algorithm. </returns>
		/// <exception cref="NoSuchAlgorithmException"> if a secret-key factory for the specified algorithm
		/// is not available in the default provider package or any of the other provider packages
		/// that were searched. </exception>
		public static SecretKeyFactory getInstance(string algorithm)
		{
			try
			{
				JCEUtil.Implementation imp = JCEUtil.getImplementation("SecretKeyFactory", algorithm, (string) null);

				if (imp == null)
				{
					throw new NoSuchAlgorithmException(algorithm + " not found");
				}

				SecretKeyFactory keyFact = new SecretKeyFactory((SecretKeyFactorySpi)imp.getEngine(), imp.getProvider(), algorithm);

				return keyFact;
			}
			catch (NoSuchProviderException)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}
		}

		/// <summary>
		/// Generates a <code>SecretKeyFactory</code> object for the specified
		/// secret-key algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested secret-key algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard algorithm names. </param>
		/// <param name="provider"> the name of the provider. </param>
		/// <returns> a <code>SecretKeyFactory</code> object for the specified secret-key algorithm. </returns>
		/// <exception cref="NoSuchAlgorithmException"> if a secret-key factory for the specified algorithm is not
		/// available from the specified provider. </exception>
		/// <exception cref="NoSuchProviderException"> if the specified provider has not been configured. </exception>
		public static SecretKeyFactory getInstance(string algorithm, string provider)
		{
			if (string.ReferenceEquals(provider, null))
			{
				throw new IllegalArgumentException("No provider specified to SecretKeyFactory.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("SecretKeyFactory", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			SecretKeyFactory keyFact = new SecretKeyFactory((SecretKeyFactorySpi)imp.getEngine(), imp.getProvider(), algorithm);

			return keyFact;
		}

		/// <summary>
		/// Generates a <code>SecretKeyFactory</code> object for the specified
		/// secret-key algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested secret-key algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard algorithm names. </param>
		/// <param name="provider"> the provider. </param>
		/// <returns> a <code>SecretKeyFactory</code> object for the specified secret-key algorithm. </returns>
		/// <exception cref="NoSuchAlgorithmException"> if a secret-key factory for the specified algorithm is not
		/// available from the specified provider. </exception>
		public static SecretKeyFactory getInstance(string algorithm, Provider provider)
		{
			if (provider == null)
			{
				throw new IllegalArgumentException("No provider specified to SecretKeyFactory.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("SecretKeyFactory", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			SecretKeyFactory keyFact = new SecretKeyFactory((SecretKeyFactorySpi)imp.getEngine(), imp.getProvider(), algorithm);

			return keyFact;
		}

		/// <summary>
		/// Returns the provider of this <code>SecretKeyFactory</code> object.
		/// </summary>
		/// <returns> the provider of this <code>SecretKeyFactory</code> object </returns>
		public Provider getProvider()
		{
			return provider;
		}

		/// <summary>
		/// Returns the algorithm name of this <code>SecretKeyFactory</code> object.
		/// <para>
		/// This is the same name that was specified in one of the <code>getInstance</code> calls
		/// that created this <code>SecretKeyFactory</code> object.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the algorithm name of this <code>SecretKeyFactory</code> object. </returns>
		public string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// Generates a <code>SecretKey</code> object from the provided key specification (key material).
		/// </summary>
		/// <param name="keySpec"> the specification (key material) of the secret key </param>
		/// <returns> the secret key </returns>
		/// <exception cref="InvalidKeySpecException"> if the given key specification
		/// is inappropriate for this secret-key factory to produce a secret key. </exception>
		public SecretKey generateSecret(KeySpec keySpec)
		{
			return keyFacSpi.engineGenerateSecret(keySpec);
		}

		/// <summary>
		/// Returns a specification (key material) of the given key object
		/// in the requested format.
		/// </summary>
		/// <param name="key"> the key </param>
		/// <param name="keySpec"> the requested format in which the key material shall be
		/// returned </param>
		/// <returns> the underlying key specification (key material) in the requested format </returns>
		/// <exception cref="InvalidKeySpecException"> if the requested key specification is inappropriate for
		/// the given key (e.g., the algorithms associated with <code>key</code> and <code>keySpec</code> do
		/// not match, or <code>key</code> references a key on a cryptographic hardware device whereas
		/// <code>keySpec</code> is the specification of a software-based key), or the given key cannot be dealt with
		/// (e.g., the given key has an algorithm or format not supported by this secret-key factory). </exception>
		public KeySpec getKeySpec(SecretKey key, Class keySpec)
		{
			return keyFacSpi.engineGetKeySpec(key, keySpec);
		}

		/// <summary>
		/// Translates a key object, whose provider may be unknown or potentially
		/// untrusted, into a corresponding key object of this secret-key factory.
		/// </summary>
		/// <param name="key"> the key whose provider is unknown or untrusted </param>
		/// <returns> the translated key </returns>
		/// <exception cref="InvalidKeyException"> if the given key cannot be processed by this secret-key factory. </exception>
		public SecretKey translateKey(SecretKey key)
		{
			return keyFacSpi.engineTranslateKey(key);
		}
	}

}