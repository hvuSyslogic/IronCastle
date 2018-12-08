namespace javax.crypto
{

	/// <summary>
	/// This class provides the functionality of a (symmetric) key generator.
	/// <para>
	/// Key generators are constructed using one of the <code>getInstance</code>
	/// class methods of this class.
	/// </para>
	/// <para>
	/// KeyGenerator objects are reusable, i.e., after a key has been
	/// generated, the same KeyGenerator object can be re-used to generate further
	/// keys.
	/// </para>
	/// <para>
	/// There are two ways to generate a key: in an algorithm-independent manner,
	/// and in an algorithm-specific manner. The only difference between the two is
	/// the initialization of the object:
	/// 
	/// <ul>
	/// <li><b>Algorithm-Independent Initialization</b>
	/// </para>
	/// <para>All key generators share the concepts of a <i>keysize</i> and a
	/// <i>source of randomness</i>.
	/// There is an 
	/// <a href = "#init(int, java.security.SecureRandom)">init</a> 
	/// method in this KeyGenerator class that takes these two universally
	/// shared types of arguments. There is also one that takes just a
	/// <code>keysize</code> argument, and uses the SecureRandom implementation
	/// of the highest-priority installed provider as the source of randomness
	/// (or a system-provided source of randomness if none of the installed
	/// providers supply a SecureRandom implementation), and one that takes just a
	/// source of randomness.
	/// </para>
	/// <para>
	/// Since no other parameters are specified when you call the above
	/// algorithm-independent <code>init</code> methods, it is up to the
	/// provider what to do about the algorithm-specific parameters (if any) to be
	/// associated with each of the keys.
	/// </para>
	/// <para>
	/// <li><b>Algorithm-Specific Initialization</b>
	/// </para>
	/// <para>For situations where a set of algorithm-specific parameters already
	/// exists, there are two
	/// <a href = "#init(java.security.spec.AlgorithmParameterSpec)">init</a>
	/// methods that have an <code>AlgorithmParameterSpec</code>
	/// argument. One also has a <code>SecureRandom</code> argument, while the
	/// other uses the SecureRandom implementation
	/// of the highest-priority installed provider as the source of randomness
	/// (or a system-provided source of randomness if none of the installed
	/// providers supply a SecureRandom implementation).
	/// </ul>
	/// 
	/// </para>
	/// <para>In case the client does not explicitly initialize the KeyGenerator
	/// (via a call to an <code>init</code> method), each provider must
	/// supply (and document) a default initialization.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SecretKey </seealso>
	public class KeyGenerator
	{
		private KeyGeneratorSpi keyGenerator;
		private Provider provider;
		private string algorithm;

		/// <summary>
		/// Creates a KeyGenerator object.
		/// </summary>
		/// <param name="keyGenSpi"> the delegate </param>
		/// <param name="provider"> the provider </param>
		/// <param name="algorithm"> the algorithm </param>
		public KeyGenerator(KeyGeneratorSpi keyGenSpi, Provider provider, string algorithm)
		{
			this.keyGenerator = keyGenSpi;
			this.provider = provider;
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Returns the algorithm name of this <code>KeyGenerator</code> object.
		/// <para>
		/// This is the same name that was specified in one of the
		/// <code>getInstance</code> calls that created this
		/// <code>KeyGenerator</code> object.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the algorithm name of this <code>KeyGenerator</code> object. </returns>
		public string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// Generates a <code>KeyGenerator</code> object for the specified algorithm.
		/// If the default provider package provides an implementation of the
		/// requested key generator, an instance of <code>KeyGenerator</code> containing
		/// that implementation is returned. If the requested key generator is not available
		/// in the default provider package, other provider packages are searched.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested key algorithm. See Appendix A in the
		/// Java Cryptography Extension API Specification &amp; Reference for information about standard
		/// algorithm names. </param>
		/// <returns> the new <code>KeyGenerator</code> object </returns>
		/// <exception cref="NoSuchAlgorithmException"> if a key generator for the specified algorithm is not
		/// available in the default provider package or any of the other provider packages that were searched. </exception>
		public static KeyGenerator getInstance(string algorithm)
		{
			try
			{
				JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyGenerator", algorithm, (string) null);

				if (imp == null)
				{
					throw new NoSuchAlgorithmException(algorithm + " not found");
				}

				KeyGenerator keyGen = new KeyGenerator((KeyGeneratorSpi)imp.getEngine(), imp.getProvider(), algorithm);

				return keyGen;
			}
			catch (NoSuchProviderException)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}
		}

		/// <summary>
		/// Generates a <code>KeyGenerator</code> object for the specified key
		/// algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested key algorithm. See Appendix A in the
		/// Java Cryptography Extension API Specification &amp; Reference for information about standard
		/// algorithm names. </param>
		/// <param name="provider"> the provider </param>
		/// <returns> the new <code>KeyGenerator</code> object </returns>
		/// <exception cref="NoSuchAlgorithmException"> if a key generator for the specified algorithm is not
		/// available from the specified provider. </exception>
		public static KeyGenerator getInstance(string algorithm, Provider provider)
		{
			if (provider == null)
			{
				throw new IllegalArgumentException("No provider specified to KeyGenerator.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyGenerator", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			KeyGenerator keyGen = new KeyGenerator((KeyGeneratorSpi)imp.getEngine(), imp.getProvider(), algorithm);

			return keyGen;
		}

		/// <summary>
		/// Generates a <code>KeyGenerator</code> object for the specified key
		/// algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested key algorithm. See Appendix A in the
		/// Java Cryptography Extension API Specification &amp; Reference for information about standard
		/// algorithm names. </param>
		/// <param name="provider"> the name of the provider </param>
		/// <returns> the new <code>KeyGenerator</code> object </returns>
		/// <exception cref="NoSuchAlgorithmException"> if a key generator for the specified algorithm is not
		/// available from the specified provider. </exception>
		/// <exception cref="NoSuchProviderException"> if the specified provider has not been configured. </exception>
		public static KeyGenerator getInstance(string algorithm, string provider)
		{
			if (string.ReferenceEquals(provider, null))
			{
				throw new IllegalArgumentException("No provider specified to KeyGenerator.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("KeyGenerator", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			KeyGenerator keyGen = new KeyGenerator((KeyGeneratorSpi)imp.getEngine(), imp.getProvider(), algorithm);

			return keyGen;
		}

		/// <summary>
		/// Returns the provider of this <code>KeyGenerator</code> object.
		/// </summary>
		/// <returns> the provider of this <code>KeyGenerator</code> object </returns>
		public Provider getProvider()
		{
			return provider;
		}

		/// <summary>
		/// Initializes this key generator.
		/// </summary>
		/// <param name="random"> the source of randomness for this generator </param>
		public void init(SecureRandom random)
		{
			keyGenerator.engineInit(random);
		}

		/// <summary>
		/// Initializes this key generator with the specified parameter set.
		/// <para>
		/// If this key generator requires any random bytes, it will get them
		/// using the * <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority installed
		/// provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// 
		/// </para>
		/// </summary>
		/// <param name="params"> the key generation parameters </param>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters are inappropriate
		/// for this key generator </exception>
		public void init(AlgorithmParameterSpec @params)
		{
			keyGenerator.engineInit(@params, new SecureRandom());
		}

		/// <summary>
		/// Initializes this key generator with the specified parameter set and a user-provided source of randomness.
		/// </summary>
		/// <param name="params"> the key generation parameters </param>
		/// <param name="random"> the source of randomness for this key generator </param>
		/// <exception cref="InvalidAlgorithmParameterException"> if <code>params</code> is inappropriate for this key generator </exception>
		public void init(AlgorithmParameterSpec @params, SecureRandom random)
		{
			keyGenerator.engineInit(@params, random);
		}

		/// <summary>
		/// Initializes this key generator for a certain keysize.
		/// <para>
		/// If this key generator requires any random bytes, it will get them using the
		/// <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority installed provider as
		/// the source of randomness. (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// 
		/// </para>
		/// </summary>
		/// <param name="keysize"> the keysize. This is an algorithm-specific metric, specified in number of bits. </param>
		/// <exception cref="InvalidParameterException"> if the keysize is wrong or not supported. </exception>
		public void init(int keysize)
		{
			keyGenerator.engineInit(keysize, new SecureRandom());
		}

		/// <summary>
		/// Initializes this key generator for a certain keysize, using a user-provided source of randomness.
		/// </summary>
		/// <param name="keysize"> the keysize. This is an algorithm-specific metric, specified in number of bits. </param>
		/// <param name="random"> the source of randomness for this key generator </param>
		/// <exception cref="InvalidParameterException"> if the keysize is wrong or not supported. </exception>
		public void init(int keysize, SecureRandom random)
		{
			keyGenerator.engineInit(keysize, random);
		}

		/// <summary>
		/// Generates a secret key.
		/// </summary>
		/// <returns> the new key </returns>
		public SecretKey generateKey()
		{
			return keyGenerator.engineGenerateKey();
		}
	}

}