namespace javax.crypto
{

	/// <summary>
	/// This class provides the functionality of a key agreement (or key
	/// exchange) protocol.
	/// The keys involved in establishing a shared secret are created by one of the
	/// key generators (<code>KeyPairGenerator</code> or
	/// <code>KeyGenerator</code>), a <code>KeyFactory</code>, or as a result from
	/// an intermediate phase of the key agreement protocol
	/// (see <a href = "#doPhase(java.security.Key, boolean)">doPhase</a>).
	/// 
	/// For each of the correspondents in the key exchange, <code>doPhase</code>
	/// needs to be called. For example, if this key exchange is with one other
	/// party, <code>doPhase</code> needs to be called once, with the
	/// <code>lastPhase</code> flag set to <code>true</code>.
	/// If this key exchange is
	/// with two other parties, <code>doPhase</code> needs to be called twice,
	/// the first time setting the <code>lastPhase</code> flag to
	/// <code>false</code>, and the second time setting it to <code>true</code>.
	/// There may be any number of parties involved in a key exchange.
	/// </summary>
	/// <seealso cref= KeyGenerator </seealso>
	/// <seealso cref= SecretKey </seealso>
	public class KeyAgreement
	{
		internal KeyAgreementSpi keyAgreeSpi;
		internal Provider provider;
		internal string algorithm;

		/// <summary>
		/// Creates a KeyAgreement object.
		/// </summary>
		/// <param name="keyAgreeSpi"> the delegate </param>
		/// <param name="provider"> the provider </param>
		/// <param name="algorithm"> the algorithm </param>
		public KeyAgreement(KeyAgreementSpi keyAgreeSpi, Provider provider, string algorithm)
		{
			this.keyAgreeSpi = keyAgreeSpi;
			this.provider = provider;
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Returns the algorithm name of this <code>KeyAgreement</code> object.
		/// <para>
		/// This is the same name that was specified in one of the
		/// <code>getInstance</code> calls that created this
		/// <code>KeyAgreement</code> object.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the algorithm name of this <code>KeyAgreement</code> object. </returns>
		public string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// Generates a <code>KeyAgreement</code> object that implements the
		/// specified key agreement algorithm.
		/// If the default provider package provides an implementation of the
		/// requested key agreement algorithm, an instance of
		/// <code>KeyAgreement</code> containing that implementation is returned.
		/// If the algorithm is not available in the default provider package,
		/// other provider packages are searched.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested key agreement algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard algorithm names. </param>
		/// <returns> the new <code>KeyAgreement</code> object </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algorithm is not
		/// available in the default provider package or any of the other provider
		/// packages that were searched. </exception>
		public static KeyAgreement getInstance(string algorithm)
		{
			try
			{
				JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyAgreement", algorithm, (string) null);

				if (imp == null)
				{
					throw new NoSuchAlgorithmException(algorithm + " not found");
				}

				KeyAgreement keyAgree = new KeyAgreement((KeyAgreementSpi)imp.getEngine(), imp.getProvider(), algorithm);

				return keyAgree;
			}
			catch (NoSuchProviderException)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}
		}

		/// <summary>
		/// Generates a <code>KeyAgreement</code> object for the specified key
		/// agreement algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested key agreement algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard algorithm names. </param>
		/// <param name="provider"> the provider </param>
		/// <returns> the new <code>KeyAgreement</code> object </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algorithm is not
		/// available from the specified provider. </exception>
		public static KeyAgreement getInstance(string algorithm, Provider provider)
		{
			if (provider == null)
			{
				throw new IllegalArgumentException("No provider specified to KeyAgreement.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyAgreement", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			KeyAgreement keyAgree = new KeyAgreement((KeyAgreementSpi)imp.getEngine(), imp.getProvider(), algorithm);

			return keyAgree;
		}

		/// <summary>
		/// Generates a <code>KeyAgreement</code> object for the specified key
		/// agreement algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested key agreement algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard algorithm names. </param>
		/// <param name="provider"> the name of the provider </param>
		/// <returns> the new <code>KeyAgreement</code> object </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algorithm is not
		/// available from the specified provider. </exception>
		/// <exception cref="NoSuchProviderException"> if the specified provider has not
		/// been configured. </exception>
		public static KeyAgreement getInstance(string algorithm, string provider)
		{
			if (string.ReferenceEquals(provider, null))
			{
				throw new IllegalArgumentException("No provider specified to KeyAgreement.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyAgreement", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			KeyAgreement keyAgree = new KeyAgreement((KeyAgreementSpi)imp.getEngine(), imp.getProvider(), algorithm);

			return keyAgree;
		}

		/// <summary>
		/// Returns the provider of this <code>KeyAgreement</code> object.
		/// </summary>
		/// <returns> the provider of this <code>KeyAgreement</code> object </returns>
		public Provider getProvider()
		{
			return provider;
		}

		/// <summary>
		/// Initializes this key agreement with the given key, which is required to
		/// contain all the algorithm parameters required for this key agreement.
		/// <para>
		/// If this key agreement requires any random bytes, it will get
		/// them using the <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority
		/// installed provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the party's private information. For example, in the case
		/// of the Diffie-Hellman key agreement, this would be the party's own
		/// Diffie-Hellman private key. </param>
		/// <exception cref="InvalidKeyException"> if the given key is
		/// inappropriate for this key agreement, e.g., is of the wrong type or
		/// has an incompatible algorithm type. </exception>
		public void init(Key key)
		{
			keyAgreeSpi.engineInit(key, null);
		}

		/// <summary>
		/// Initializes this key agreement with the given key and source of
		/// randomness. The given key is required to contain all the algorithm
		/// parameters required for this key agreement.
		/// <para>
		/// If the key agreement algorithm requires random bytes, it gets them
		/// from the given source of randomness, <code>random</code>.
		/// However, if the underlying
		/// algorithm implementation does not require any random bytes,
		/// <code>random</code> is ignored.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the party's private information. For example, in the case
		/// of the Diffie-Hellman key agreement, this would be the party's own
		/// Diffie-Hellman private key. </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is
		/// inappropriate for this key agreement, e.g., is of the wrong type or
		/// has an incompatible algorithm type. </exception>
		public void init(Key key, SecureRandom random)
		{
			keyAgreeSpi.engineInit(key, random);
		}

		/// <summary>
		/// Initializes this key agreement with the given key and set of
		/// algorithm parameters.
		/// <para>
		/// If this key agreement requires any random bytes, it will get
		/// them using the <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority
		/// installed provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the party's private information. For example, in the case
		/// of the Diffie-Hellman key agreement, this would be the party's own
		/// Diffie-Hellman private key. </param>
		/// <param name="params"> the key agreement parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for this
		/// key agreement, e.g., is of the wrong type or has an incompatible algorithm type. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters
		/// are inappropriate for this key agreement. </exception>
		public void init(Key key, AlgorithmParameterSpec @params)
		{
			keyAgreeSpi.engineInit(key, @params, null);
		}

		/// <summary>
		/// Initializes this key agreement with the given key, set of
		/// algorithm parameters, and source of randomness.
		/// </summary>
		/// <param name="key"> the party's private information. For example, in the case
		/// of the Diffie-Hellman key agreement, this would be the party's own
		/// Diffie-Hellman private key. </param>
		/// <param name="params"> the key agreement parameters </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is
		/// inappropriate for this key agreement, e.g., is of the wrong type or
		/// has an incompatible algorithm type. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters
		/// are inappropriate for this key agreement. </exception>
		public void init(Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			keyAgreeSpi.engineInit(key, @params, random);
		}

		/// <summary>
		/// Executes the next phase of this key agreement with the given
		/// key that was received from one of the other parties involved in this key
		/// agreement.
		/// </summary>
		/// <param name="key"> the key for this phase. For example, in the case of
		/// Diffie-Hellman between 2 parties, this would be the other party's
		/// Diffie-Hellman public key. </param>
		/// <param name="lastPhase"> flag which indicates whether or not this is the last
		/// phase of this key agreement. </param>
		/// <returns> the (intermediate) key resulting from this phase, or null
		/// if this phase does not yield a key </returns>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for this phase. </exception>
		/// <exception cref="IllegalStateException"> if this key agreement has not been
		/// initialized. </exception>
		public Key doPhase(Key key, bool lastPhase)
		{
			return keyAgreeSpi.engineDoPhase(key, lastPhase);
		}

		/// <summary>
		/// Generates the shared secret and returns it in a new buffer.
		/// <para>
		/// This method resets this <code>KeyAgreement</code> object, so that it
		/// can be reused for further key agreements. Unless this key agreement is
		/// reinitialized with one of the <code>init</code> methods, the same
		/// private information and algorithm parameters will be used for
		/// subsequent key agreements.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the new buffer with the shared secret </returns>
		/// <exception cref="IllegalStateException"> if this key agreement has not been completed yet </exception>
		public byte[] generateSecret()
		{
			return keyAgreeSpi.engineGenerateSecret();
		}

		/// <summary>
		/// Generates the shared secret, and places it into the buffer
		/// <code>sharedSecret</code>, beginning at <code>offset</code> inclusive.
		/// <para>
		/// If the <code>sharedSecret</code> buffer is too small to hold the
		/// result, a <code>ShortBufferException</code> is thrown.
		/// In this case, this call should be repeated with a larger output buffer. 
		/// </para>
		/// <para>
		/// This method resets this <code>KeyAgreement</code> object, so that it
		/// can be reused for further key agreements. Unless this key agreement is
		/// reinitialized with one of the <code>init</code> methods, the same
		/// private information and algorithm parameters will be used for
		/// subsequent key agreements.
		/// 
		/// </para>
		/// </summary>
		/// <param name="sharedSecret"> the buffer for the shared secret </param>
		/// <param name="offset"> the offset in <code>sharedSecret</code> where the
		/// shared secret will be stored </param>
		/// <returns> the number of bytes placed into <code>sharedSecret</code> </returns>
		/// <exception cref="IllegalStateException"> if this key agreement has not been
		/// completed yet </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small
		/// to hold the secret </exception>
		public int generateSecret(byte[] sharedSecret, int offset)
		{
			return keyAgreeSpi.engineGenerateSecret(sharedSecret, offset);
		}

		/// <summary>
		/// Creates the shared secret and returns it as a <code>SecretKey</code>
		/// object of the specified algorithm.
		/// <para>
		/// This method resets this <code>KeyAgreement</code> object, so that it
		/// can be reused for further key agreements. Unless this key agreement is
		/// reinitialized with one of the <code>init</code> methods, the same
		/// private information and algorithm parameters will be used for
		/// subsequent key agreements.
		/// 
		/// </para>
		/// </summary>
		/// <param name="algorithm"> the requested secret-key algorithm </param>
		/// <returns> the shared secret key </returns>
		/// <exception cref="IllegalStateException"> if this key agreement has not been
		/// completed yet </exception>
		/// <exception cref="NoSuchAlgorithmException"> if the specified secret-key
		/// algorithm is not available </exception>
		/// <exception cref="InvalidKeyException"> if the shared secret-key material cannot
		/// be used to generate a secret key of the specified algorithm (e.g.,
		/// the key material is too short) </exception>
		public SecretKey generateSecret(string algorithm)
		{
			return keyAgreeSpi.engineGenerateSecret(algorithm);
		}
	}

}