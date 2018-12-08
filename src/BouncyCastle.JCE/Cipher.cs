namespace javax.crypto
{

	/// <summary>
	/// This class provides the functionality of a cryptographic cipher for
	/// encryption and decryption. It forms the core of the Java Cryptographic
	/// Extension (JCE) framework.
	/// <para>
	/// In order to create a Cipher object, the application calls the
	/// Cipher's <code>getInstance</code> method, and passes the name of the
	/// requested <i>transformation</i> to it. Optionally, the name of a provider
	/// may be specified.
	/// </para>
	/// <para>
	/// A <i>transformation</i> is a string that describes the operation (or
	/// set of operations) to be performed on the given input, to produce some
	/// output. A transformation always includes the name of a cryptographic
	/// algorithm (e.g., <i>DES</i>), and may be followed by a feedback mode and
	/// padding scheme.
	/// 
	/// </para>
	/// <para> A transformation is of the form:<p>
	/// 
	/// <ul>
	/// <li>"<i>algorithm/mode/padding</i>" or
	/// </para>
	/// <para>
	/// <li>"<i>algorithm</i>"
	/// </ul>
	/// 
	/// <P> (in the latter case,
	/// provider-specific default values for the mode and padding scheme are used).
	/// </para>
	/// For example, the following is a valid transformation:<para>
	/// 
	/// <pre>
	///     Cipher c = Cipher.getInstance("<i>DES/CBC/PKCS5Padding</i>");
	/// </pre>
	/// </para>
	/// <para>
	/// When requesting a block cipher in stream cipher mode (e.g.,
	/// <code>DES</code> in <code>CFB</code> or <code>OFB</code> mode), the user may
	/// optionally specify the number of bits to be
	/// processed at a time, by appending this number to the mode name as shown in
	/// the "<i>DES/CFB8/NoPadding</i>" and "<i>DES/OFB32/PKCS5Padding</i>"
	/// transformations. If no such number is specified, a provider-specific default
	/// is used. (For example, the "SunJCE" provider uses a default of 64 bits.)
	/// </para>
	/// </summary>
	public class Cipher
	{
		private const int UNINITIALIZED = 0;

		public const int ENCRYPT_MODE = 1;
		public const int DECRYPT_MODE = 2;
		public const int WRAP_MODE = 3;
		public const int UNWRAP_MODE = 4;

		public const int PUBLIC_KEY = 1;
		public const int PRIVATE_KEY = 2;
		public const int SECRET_KEY = 3;

		private CipherSpi cipherSpi;
		private Provider provider;
		private string transformation;

		private int mode = UNINITIALIZED;

		/// <summary>
		/// Creates a Cipher object.
		/// </summary>
		/// <param name="cipherSpi"> the delegate </param>
		/// <param name="provider"> the provider </param>
		/// <param name="transformation"> the transformation </param>
		public Cipher(CipherSpi cipherSpi, Provider provider, string transformation)
		{
			this.cipherSpi = cipherSpi;
			this.provider = provider;
			this.transformation = transformation;
		}

		/// <summary>
		/// Generates a <code>Cipher</code> object that implements the specified
		/// transformation.
		/// <para>
		/// If the default provider package supplies an implementation of the
		/// requested transformation, an instance of <code>Cipher</code> containing
		/// that implementation is returned.
		/// If the transformation is not available in the default provider package,
		/// other provider packages are searched.
		/// 
		/// </para>
		/// </summary>
		/// <param name="transformation"> the name of the transformation, e.g., <i>DES/CBC/PKCS5Padding</i>.
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference
		/// for information about standard transformation names.
		/// </param>
		/// <returns> a cipher that implements the requested transformation </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified transformation is not available in the default
		/// provider package or any of the other provider packages that were searched. </exception>
		/// <exception cref="NoSuchPaddingException"> if <code>transformation</code> contains a padding scheme that is
		/// not available. </exception>
		public static Cipher getInstance(string transformation)
		{
			try
			{
				JCEUtil.Implementation imp = JCEUtil.getImplementation("Cipher", transformation, (string) null);

				if (imp != null)
				{
					return new Cipher((CipherSpi)imp.getEngine(), imp.getProvider(), transformation);
				}

				//
				// try the long way
				//
				StringTokenizer tok = new StringTokenizer(transformation, "/");
				string algorithm = tok.nextToken();

				imp = JCEUtil.getImplementation("Cipher", algorithm, (string) null);

				if (imp == null)
				{
					throw new NoSuchAlgorithmException(transformation + " not found");
				}

				CipherSpi cipherSpi = (CipherSpi)imp.getEngine();

				//
				// make sure we don't get fooled by a "//" in the string
				//
				if (tok.hasMoreTokens() && !transformation.regionMatches(algorithm.Length, "//", 0, 2))
				{
					cipherSpi.engineSetMode(tok.nextToken());
				}

				if (tok.hasMoreTokens())
				{
					cipherSpi.engineSetPadding(tok.nextToken());
				}

				return new Cipher(cipherSpi, imp.getProvider(), transformation);
			}
			catch (NoSuchProviderException)
			{
				throw new NoSuchAlgorithmException(transformation + " not found");
			}
		}

		/// <summary>
		/// Creates a <code>Cipher</code> object that implements the specified
		/// transformation, as supplied by the specified provider.
		/// </summary>
		/// <param name="transformation"> the name of the transformation, e.g., <i>DES/CBC/PKCS5Padding</i>.
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard transformation names.
		/// </param>
		/// <param name="provider"> the provider </param>
		/// <returns> a cipher that implements the requested transformation </returns>
		/// <exception cref="NoSuchAlgorithmException"> if no transformation was specified, or if the specified
		/// transformation is not available from the specified provider. </exception>
		/// <exception cref="NoSuchPaddingException"> if <code>transformation</code> contains a padding scheme
		/// that is not available. </exception>
		public static Cipher getInstance(string transformation, Provider provider)
		{
			if (string.ReferenceEquals(transformation, null))
			{
				throw new IllegalArgumentException("No transformation specified for Cipher.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("Cipher", transformation, provider);

			if (imp != null)
			{
				return new Cipher((CipherSpi)imp.getEngine(), imp.getProvider(), transformation);
			}

			//
			// try the long way
			//
			StringTokenizer tok = new StringTokenizer(transformation, "/");
			string algorithm = tok.nextToken();

			imp = JCEUtil.getImplementation("Cipher", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(transformation + " not found");
			}

			CipherSpi cipherSpi = (CipherSpi)imp.getEngine();

			//
			// make sure we don't get fooled by a "//" in the string
			//
			if (tok.hasMoreTokens() && !transformation.regionMatches(algorithm.Length, "//", 0, 2))
			{
				cipherSpi.engineSetMode(tok.nextToken());
			}

			if (tok.hasMoreTokens())
			{
				cipherSpi.engineSetPadding(tok.nextToken());
			}

			return new Cipher(cipherSpi, imp.getProvider(), transformation);
		}

		/// <summary>
		/// Creates a <code>Cipher</code> object that implements the specified
		/// transformation, as supplied by the specified provider.
		/// </summary>
		/// <param name="transformation"> the name of the transformation, e.g., <i>DES/CBC/PKCS5Padding</i>.
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard transformation names.
		/// </param>
		/// <param name="provider"> the name of the provider </param>
		/// <returns> a cipher that implements the requested transformation </returns>
		/// <exception cref="NoSuchAlgorithmException"> if no transformation was specified, or if the specified
		/// transformation is not available from the specified provider. </exception>
		/// <exception cref="NoSuchProviderException"> if the specified provider has not been configured. </exception>
		/// <exception cref="NoSuchPaddingException"> if <code>transformation</code> contains a padding scheme
		/// that is not available. </exception>
		public static Cipher getInstance(string transformation, string provider)
		{
			if (string.ReferenceEquals(transformation, null))
			{
				throw new IllegalArgumentException("No transformation specified for Cipher.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("Cipher", transformation, provider);

			if (imp != null)
			{
				return new Cipher((CipherSpi)imp.getEngine(), imp.getProvider(), transformation);
			}

			//
			// try the long way
			//
			StringTokenizer tok = new StringTokenizer(transformation, "/");
			string algorithm = tok.nextToken();

			imp = JCEUtil.getImplementation("Cipher", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(transformation + " not found");
			}

			CipherSpi cipherSpi = (CipherSpi)imp.getEngine();

			//
			// make sure we don't get fooled by a "//" in the string
			//
			if (tok.hasMoreTokens() && !transformation.regionMatches(algorithm.Length, "//", 0, 2))
			{
				cipherSpi.engineSetMode(tok.nextToken());
			}

			if (tok.hasMoreTokens())
			{
				cipherSpi.engineSetPadding(tok.nextToken());
			}

			return new Cipher(cipherSpi, imp.getProvider(), transformation);
		}

		/// <summary>
		/// Returns the provider of this <code>Cipher</code> object.
		/// </summary>
		/// <returns> the provider of this <code>Cipher</code> object </returns>
		public Provider getProvider()
		{
			return provider;
		}

		/// <summary>
		/// Returns the algorithm name of this <code>Cipher</code> object.
		/// <para>
		/// This is the same name that was specified in one of the
		/// <code>getInstance</code> calls that created this <code>Cipher</code>
		/// object..
		/// 
		/// </para>
		/// </summary>
		/// <returns> the algorithm name of this <code>Cipher</code> object. </returns>
		public string getAlgorithm()
		{
			return transformation;
		}

		/// <summary>
		/// Returns the block size (in bytes).
		/// </summary>
		/// <returns> the block size (in bytes), or 0 if the underlying algorithm is not a block cipher </returns>
		public int getBlockSize()
		{
			return cipherSpi.engineGetBlockSize();
		}

		/// <summary>
		/// Returns the length in bytes that an output buffer would need to be in
		/// order to hold the result of the next <code>update</code> or
		/// <code>doFinal</code> operation, given the input length <code>inputLen</code> (in bytes).
		/// <para>
		/// This call takes into account any unprocessed (buffered) data from a
		/// previous <code>update</code> call, and padding.
		/// </para>
		/// <para>
		/// The actual output length of the next <code>update</code> or
		/// <code>doFinal</code> call may be smaller than the length returned by
		/// this method.
		/// 
		/// </para>
		/// </summary>
		/// <param name="inputLen"> the input length (in bytes) </param>
		/// <returns> the required output buffer size (in bytes) </returns>
		/// <exception cref="java.lang.IllegalStateException"> if this cipher is in a wrong state (e.g., has not
		/// yet been initialized) </exception>
		public int getOutputSize(int inputLen)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			return cipherSpi.engineGetOutputSize(inputLen);
		}

		/// <summary>
		/// Returns the initialization vector (IV) in a new buffer.
		/// <para>
		/// This is useful in the case where a random IV was created,
		/// or in the context of password-based encryption or decryption, where the IV
		/// is derived from a user-supplied password.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the initialization vector in a new buffer, or null if the
		/// underlying algorithm does not use an IV, or if the IV has not yet been set. </returns>
		public byte[] getIV()
		{
			return cipherSpi.engineGetIV();
		}

		/// <summary>
		/// Returns the parameters used with this cipher.
		/// <para>
		/// The returned parameters may be the same that were used to initialize
		/// this cipher, or may contain a combination of default and random
		/// parameter values used by the underlying cipher implementation if this
		/// cipher requires algorithm parameters but was not initialized with any.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the parameters used with this cipher, or null if this cipher
		/// does not use any parameters. </returns>
		public AlgorithmParameters getParameters()
		{
			return cipherSpi.engineGetParameters();
		}

		/// <summary>
		/// Returns the exemption mechanism object used with this cipher.
		/// </summary>
		/// <returns> the exemption mechanism object used with this cipher, or
		/// null if this cipher does not use any exemption mechanism. </returns>
		public ExemptionMechanism getExemptionMechanism()
		{
			return null;
		}

		/// <summary>
		/// Initializes this cipher with a key.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be
		/// derived from the given <code>key</code>, the underlying cipher
		/// implementation is supposed to generate the required parameters itself
		/// (using provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidKeyException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#getParameters()">getParameters</a> or
		/// <a href = "#getIV()">getIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them using the <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority
		/// installed provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the following:
		/// <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the key </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for
		/// initializing this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters that cannot be
		/// determined from the given key, or if the given key has a keysize that
		/// exceeds the maximum allowable keysize (as determined from the
		/// configured jurisdiction policy files). Note: Jurisdiction files are ignored
		/// in this implementation. </exception>
		public void init(int opmode, Key key)
		{
			cipherSpi.engineInit(opmode, key, new SecureRandom());
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with a key and a source of randomness.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or  key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be
		/// derived from the given <code>key</code>, the underlying cipher
		/// implementation is supposed to generate the required parameters itself
		/// (using provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidKeyException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#engineGetParameters()">engineGetParameters</a> or
		/// <a href = "#engineGetIV()">engineGetIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from <code>random</code>.
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for
		/// initializing this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters that cannot be
		/// determined from the given key, or if the given key has a keysize that
		/// exceeds the maximum allowable keysize (as determined from the
		/// configured jurisdiction policy files). Note: Jurisdiction files are ignored
		/// in this implementation. </exception>
		public void init(int opmode, Key key, SecureRandom random)
		{
			cipherSpi.engineInit(opmode, key, random);
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with a key and a set of algorithm parameters.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or  key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters and
		/// <code>params</code> is null, the underlying cipher implementation is
		/// supposed to generate the required parameters itself (using
		/// provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidAlgorithmParameterException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#getParameters()">getParameters</a> or
		/// <a href = "#getIV()">getIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them using the
		/// <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority
		/// installed provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
		/// or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher, or its keysize exceeds the maximum allowable keysize (as determined from the
		/// configured jurisdiction policy files). </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are
		/// inappropriate for this cipher, or this cipher is being initialized for decryption and
		/// requires algorithm parameters and <code>params</code> is null, or the given algorithm
		/// parameters imply a cryptographic strength that would exceed the legal limits (as determined
		/// from the configured jurisdiction policy files). Note: Jurisdiction files are ignored
		/// in this implementation. </exception>
		public void init(int opmode, Key key, AlgorithmParameterSpec @params)
		{
			cipherSpi.engineInit(opmode, key, @params, new SecureRandom());
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with a key, a set of algorithm
		/// parameters, and a source of randomness.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or  key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters and
		/// <code>params</code> is null, the underlying cipher implementation is
		/// supposed to generate the required parameters itself (using
		/// provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidAlgorithmParameterException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#getParameters()">getParameters</a> or
		/// <a href = "#getIV()">getIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from <code>random</code>.
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for
		/// initializing this cipher, or its keysize exceeds the maximum allowable
		/// keysize (as determined from the configured jurisdiction policy files). </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm
		/// parameters are inappropriate for this cipher,
		/// or this cipher is being initialized for decryption and requires
		/// algorithm parameters and <code>params</code> is null, or the given
		/// algorithm parameters imply a cryptographic strength that would exceed
		/// the legal limits (as determined from the configured jurisdiction
		/// policy files).
		/// Note: Jurisdiction files are ignored in this implementation. </exception>
		public void init(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			cipherSpi.engineInit(opmode, key, @params, random);
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with a key and a set of algorithm
		/// parameters.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or  key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters and
		/// <code>params</code> is null, the underlying cipher implementation is
		/// supposed to generate the required parameters itself (using
		/// provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidAlgorithmParameterException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#getParameters()">getParameters</a> or
		/// <a href = "#getIV()">getIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them using the
		/// <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a> implementation of the highest-priority
		/// installed provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
		/// or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for
		/// initializing this cipher, or its keysize exceeds the maximum allowable
		/// keysize (as determined from the configured jurisdiction policy files). </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm
		/// parameters are inappropriate for this cipher,
		/// or this cipher is being initialized for decryption and requires
		/// algorithm parameters and <code>params</code> is null, or the given
		/// algorithm parameters imply a cryptographic strength that would exceed
		/// the legal limits (as determined from the configured jurisdiction
		/// policy files).
		/// Note: Jurisdiction files are ignored in this implementation. </exception>
		public void init(int opmode, Key key, AlgorithmParameters @params)
		{
			cipherSpi.engineInit(opmode, key, @params, new SecureRandom());
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with a key, a set of algorithm
		/// parameters, and a source of randomness.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or  key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters and
		/// <code>params</code> is null, the underlying cipher implementation is
		/// supposed to generate the required parameters itself (using
		/// provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidAlgorithmParameterException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#getParameters()">getParameters</a> or
		/// <a href = "#getIV()">getIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from <code>random</code>.
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
		/// or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for
		/// initializing this cipher, or its keysize exceeds the maximum allowable
		/// keysize (as determined from the configured jurisdiction policy files). </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm
		/// parameters are inappropriate for this cipher,
		/// or this cipher is being initialized for decryption and requires
		/// algorithm parameters and <code>params</code> is null, or the given
		/// algorithm parameters imply a cryptographic strength that would exceed
		/// the legal limits (as determined from the configured jurisdiction
		/// policy files).
		/// Note: Jurisdiction files are ignored in this implementation. </exception>
		public void init(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
		{
			cipherSpi.engineInit(opmode, key, @params, random);
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with the public key from the given certificate.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or  key unwrapping, depending
		/// on the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If the certificate is of type X.509 and has a <i>key usage</i>
		/// extension field marked as critical, and the value of the <i>key usage</i>
		/// extension field implies that the public key in
		/// the certificate and its corresponding private key are not
		/// supposed to be used for the operation represented by the value 
		/// of <code>opmode</code>,
		/// an <code>InvalidKeyException</code>
		/// is thrown.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be
		/// derived from the public key in the given certificate, the underlying 
		/// cipher
		/// implementation is supposed to generate the required parameters itself
		/// (using provider-specific default or ramdom values) if it is being
		/// initialized for encryption or key wrapping, and raise an <code>
		/// InvalidKeyException</code> if it is being initialized for decryption or 
		/// key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#getParameters()">getParameters</a> or
		/// <a href = "#getIV()">getIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them using the
		/// <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.SecureRandom.html">
		/// <code>SecureRandom</code></a>
		/// implementation of the highest-priority installed provider as the source of randomness.
		/// (If none of the installed providers supply an implementation of
		/// SecureRandom, a system-provided source of randomness will be used.)
		/// </para>
		/// <para>
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following:
		/// <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="certificate"> the certificate </param>
		/// <exception cref="InvalidKeyException"> if the public key in the given
		/// certificate is inappropriate for initializing this cipher, or this
		/// cipher is being initialized for decryption or unwrapping keys and
		/// requires algorithm parameters that cannot be determined from the
		/// public key in the given certificate, or the keysize of the public key
		/// in the given certificate has a keysize that exceeds the maximum
		/// allowable keysize (as determined by the configured jurisdiction policy
		/// files).
		/// Note: Jurisdiction files are ignored in this implementation. </exception>
		public void init(int opmode, Certificate certificate)
		{
			cipherSpi.engineInit(opmode, certificate.getPublicKey(), new SecureRandom());
			mode = opmode;
		}

		/// <summary>
		/// Initializes this cipher with the public key from the given certificate
		/// and a source of randomness.
		/// <para>The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping
		/// or key unwrapping, depending on
		/// the value of <code>opmode</code>.
		/// </para>
		/// <para>  
		/// If the certificate is of type X.509 and has a <i>key usage</i>
		/// extension field marked as critical, and the value of the <i>key usage</i>
		/// extension field implies that the public key in
		/// the certificate and its corresponding private key are not
		/// supposed to be used for the operation represented by the value of
		/// <code>opmode</code>,
		/// an <code>InvalidKeyException</code>
		/// is thrown.
		/// </para>
		/// <para>  
		/// If this cipher requires any algorithm parameters that cannot be
		/// derived from the public key in the given <code>certificate</code>,
		/// the underlying cipher
		/// implementation is supposed to generate the required parameters itself
		/// (using provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidKeyException</code> if it is being
		/// initialized for decryption or key unwrapping.
		/// The generated parameters can be retrieved using
		/// <a href = "#engineGetParameters()">engineGetParameters</a> or
		/// <a href = "#engineGetIV()">engineGetIV</a> (if the parameter is an IV).
		/// </para>
		/// <para>  
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from <code>random</code>.
		/// </para>
		/// <para>  
		/// Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the
		/// following: <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="certificate"> the certificate </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the public key in the given
		/// certificate is inappropriate for initializing this cipher, or this
		/// cipher is being initialized for decryption or unwrapping keys and
		/// requires algorithm parameters that cannot be determined from the
		/// public key in the given certificate, or the keysize of the public key
		/// in the given certificate has a keysize that exceeds the maximum
		/// allowable keysize (as determined by the configured jurisdiction policy
		/// files). </exception>
		public void init(int opmode, Certificate certificate, SecureRandom random)
		{
			cipherSpi.engineInit(opmode, certificate.getPublicKey(), random);
			mode = opmode;
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation
		/// (depending on how this cipher was initialized), processing another data
		/// part.
		/// <para>
		/// The bytes in the <code>input</code> buffer are processed, and the
		/// result is stored in a new buffer.
		/// </para>
		/// <para>
		/// If <code>input</code> has a length of zero, this method returns
		/// <code>null</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <returns> the new buffer with the result, or null if the underlying
		/// cipher is a block cipher and the input data is too short to result in a
		/// new block. </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		public byte[] update(byte[] input)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input buffer");
			}

			if (input.Length == 0)
			{
				return null;
			}

			return cipherSpi.engineUpdate(input, 0, input.Length);
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation
		/// (depending on how this cipher was initialized), processing another data
		/// part.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, are processed,
		/// and the result is stored in a new buffer.
		/// </para>
		/// <para>
		/// If <code>inputLen</code> is zero, this method returns
		/// <code>null</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input
		/// starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <returns> the new buffer with the result, or null if the underlying
		/// cipher is a block cipher and the input data is too short to result in a
		/// new block. </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		public byte[] update(byte[] input, int inputOffset, int inputLen)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (inputLen < 0 || inputOffset < 0 || inputLen > (input.Length - inputOffset))
			{
				throw new IllegalArgumentException("Bad inputOffset/inputLen");
			}

			if (inputLen == 0)
			{
				return null;
			}

			return cipherSpi.engineUpdate(input, inputOffset, inputLen);
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation
		/// (depending on how this cipher was initialized), processing another data
		/// part.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, are processed,
		/// and the result is stored in the <code>output</code> buffer.
		/// </para>
		/// <para>
		/// If the <code>output</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown. In this case, repeat this
		/// call with a larger output buffer. Use 
		/// <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
		/// the output buffer should be.
		/// </para>
		/// <para>
		/// If <code>inputLen</code> is zero, this method returns
		/// a length of zero.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small
		/// to hold the result </exception>
		public int update(byte[] input, int inputOffset, int inputLen, byte[] output)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (inputLen < 0 || inputOffset < 0 || inputLen > (input.Length - inputOffset))
			{
				throw new IllegalArgumentException("Bad inputOffset/inputLen");
			}

			if (output == null)
			{
				throw new IllegalArgumentException("Null output passed");
			}

			if (inputLen == 0)
			{
				return 0;
			}

			return cipherSpi.engineUpdate(input, inputOffset, inputLen, output, 0);
		}

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation
		/// (depending on how this cipher was initialized), processing another data
		/// part.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, are processed,
		/// and the result is stored in the <code>output</code> buffer, starting at
		/// <code>outputOffset</code> inclusive.
		/// </para>
		/// <para>
		/// If the <code>output</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown. In this case, repeat this
		/// call with a larger output buffer. Use 
		/// <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
		/// the output buffer should be.
		/// </para>
		/// <para>
		/// If <code>inputLen</code> is zero, this method returns
		/// a length of zero.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <param name="outputOffset"> the offset in <code>output</code> where the result
		/// is stored </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small
		/// to hold the result </exception>
		public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (inputLen < 0 || inputOffset < 0 || inputLen > (input.Length - inputOffset))
			{
				throw new IllegalArgumentException("Bad inputOffset/inputLen");
			}

			if (output == null)
			{
				throw new IllegalArgumentException("Null output passed");
			}

			if (outputOffset < 0 || outputOffset >= output.Length)
			{
				throw new IllegalArgumentException("Bad outputOffset");
			}

			if (inputLen == 0)
			{
				return 0;
			}

			return cipherSpi.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
		}

		/// <summary>
		/// Finishes a multiple-part encryption or decryption operation, depending
		/// on how this cipher was initialized.
		/// <para>
		/// Input data that may have been buffered during a previous
		/// <code>update</code> operation is processed, with padding (if requested)
		/// being applied.
		/// The result is stored in a new buffer.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>init</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>init</code>) more data.
		/// </para>
		/// </summary>
		/// <returns> the new buffer with the result </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher,
		/// no padding has been requested (only in encryption mode), and the total
		/// input length of the data processed by this cipher is not a multiple of
		/// block size </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode,
		/// and (un)padding has been requested, but the decrypted data is not
		/// bounded by the appropriate padding bytes </exception>
		public byte[] doFinal()
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			return cipherSpi.engineDoFinal(null, 0, 0);
		}

		/// <summary>
		/// Finishes a multiple-part encryption or decryption operation, depending
		/// on how this cipher was initialized.
		/// <para>
		/// Input data that may have been buffered during a previous
		/// <code>update</code> operation is processed, with padding (if requested)
		/// being applied.
		/// The result is stored in the <code>output</code> buffer, starting at
		/// <code>outputOffset</code> inclusive.
		/// </para>
		/// <para>
		/// If the <code>output</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown. In this case, repeat this
		/// call with a larger output buffer. Use 
		/// <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
		/// the output buffer should be.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>init</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>init</code>) more data.
		/// 
		/// </para>
		/// </summary>
		/// <param name="output"> the buffer for the result </param>
		/// <param name="outputOffset"> the offset in <code>output</code> where the result
		/// is stored </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher,
		/// no padding has been requested (only in encryption mode), and the total
		/// input length of the data processed by this cipher is not a multiple of
		/// block size </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small
		/// to hold the result </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode,
		/// and (un)padding has been requested, but the decrypted data is not
		/// bounded by the appropriate padding bytes </exception>
		public int doFinal(byte[] output, int outputOffset)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (output == null)
			{
				throw new IllegalArgumentException("Null output passed");
			}

			if (outputOffset < 0 || outputOffset >= output.Length)
			{
				throw new IllegalArgumentException("Bad outputOffset");
			}

			return cipherSpi.engineDoFinal(null, 0, 0, output, outputOffset);
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a
		/// multiple-part operation. The data is encrypted or decrypted,
		/// depending on how this cipher was initialized.
		/// <para>
		/// The bytes in the <code>input</code> buffer, and any input bytes that
		/// may have been buffered during a previous <code>update</code> operation,
		/// are processed, with padding (if requested) being applied.
		/// The result is stored in a new buffer.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>init</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>init</code>) more data.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <returns> the new buffer with the result </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher,
		/// no padding has been requested (only in encryption mode), and the total
		/// input length of the data processed by this cipher is not a multiple of
		/// block size </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode,
		/// and (un)padding has been requested, but the decrypted data is not
		/// bounded by the appropriate padding bytes </exception>
		public byte[] doFinal(byte[] input)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			return cipherSpi.engineDoFinal(input, 0, input.Length);
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a
		/// multiple-part operation. The data is encrypted or decrypted,
		/// depending on how this cipher was initialized.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, and any input
		/// bytes that may have been buffered during a previous <code>update</code>
		/// operation, are processed, with padding (if requested) being applied.
		/// The result is stored in a new buffer.
		/// </para>
		/// <para>A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>init</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>init</code>) more data.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <returns> the new buffer with the result </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher,
		/// no padding has been requested (only in encryption mode), and the total
		/// input length of the data processed by this cipher is not a multiple of
		/// block size </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode,
		/// and (un)padding has been requested, but the decrypted data is not
		/// bounded by the appropriate padding bytes </exception>
		public byte[] doFinal(byte[] input, int inputOffset, int inputLen)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (inputLen < 0 || inputOffset < 0 || inputLen > (input.Length - inputOffset))
			{
				throw new IllegalArgumentException("Bad inputOffset/inputLen");
			}

			return cipherSpi.engineDoFinal(input, inputOffset, inputLen);
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a
		/// multiple-part operation. The data is encrypted or decrypted,
		/// depending on how this cipher was initialized.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, and any input
		/// bytes that may have been buffered during a previous <code>update</code>
		/// operation, are processed, with padding (if requested) being applied.
		/// The result is stored in the <code>output</code> buffer.
		/// </para>
		/// <para>
		/// If the <code>output</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown. In this case, repeat this
		/// call with a larger output buffer. Use 
		/// <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
		/// the output buffer should be.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>init</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>init</code>) more data.
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher,
		/// no padding has been requested (only in encryption mode), and the total
		/// input length of the data processed by this cipher is not a multiple of
		/// block size </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small
		/// to hold the result </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode,
		/// and (un)padding has been requested, but the decrypted data is not
		/// bounded by the appropriate padding bytes </exception>
		public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (inputLen < 0 || inputOffset < 0 || inputLen > (input.Length - inputOffset))
			{
				throw new IllegalArgumentException("Bad inputOffset/inputLen");
			}

			if (output == null)
			{
				throw new IllegalArgumentException("Null output passed");
			}

			return cipherSpi.engineDoFinal(input, inputOffset, inputLen, output, 0);
		}

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a
		/// multiple-part operation. The data is encrypted or decrypted,
		/// depending on how this cipher was initialized.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, and any input
		/// bytes that may have been buffered during a previous
		/// <code>update</code> operation, are processed, with padding
		/// (if requested) being applied.
		/// The result is stored in the <code>output</code> buffer, starting at
		/// <code>outputOffset</code> inclusive.
		/// </para>
		/// <para>
		/// If the <code>output</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown. In this case, repeat this
		/// call with a larger output buffer. Use 
		/// <a href = "#getOutputSize(int)">getOutputSize</a> to determine how big
		/// the output buffer should be.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>init</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>init</code>) more data.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <param name="outputOffset"> the offset in <code>output</code> where the result is
		/// stored </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized) </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher,
		/// no padding has been requested (only in encryption mode), and the total
		/// input length of the data processed by this cipher is not a multiple of
		/// block size </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small
		/// to hold the result </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode,
		/// and (un)padding has been requested, but the decrypted data is not
		/// bounded by the appropriate padding bytes </exception>
		public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
		{
			if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE)
			{
				throw new IllegalStateException("Cipher is uninitialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (inputLen < 0 || inputOffset < 0 || inputLen > (input.Length - inputOffset))
			{
				throw new IllegalArgumentException("Bad inputOffset/inputLen");
			}

			if (output == null)
			{
				throw new IllegalArgumentException("Null output passed");
			}

			if (outputOffset < 0 || outputOffset >= output.Length)
			{
				throw new IllegalArgumentException("Bad outputOffset");
			}

			return cipherSpi.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
		}

		/// <summary>
		/// Wrap a key.
		/// </summary>
		/// <param name="key"> the key to be wrapped. </param>
		/// <returns> the wrapped key. </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state (e.g., has not
		/// been initialized). </exception>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher, no padding
		/// has been requested, and the length of the encoding of the key to be wrapped is not a
		/// multiple of the block size. </exception>
		/// @exception <DD>java.security.InvalidKeyException - if it is impossible or unsafe to
		/// wrap the key with this cipher (e.g., a hardware protected key is being passed to a
		/// software-only cipher). </exception>
		public byte[] wrap(Key key)
		{
			if (mode != WRAP_MODE)
			{
				throw new IllegalStateException("Cipher is not initialised for wrapping");
			}

			if (key == null)
			{
				throw new IllegalArgumentException("Null key passed");
			}

			return cipherSpi.engineWrap(key);
		}

		/// <summary>
		/// Unwrap a previously wrapped key.
		/// </summary>
		/// <param name="wrappedKey"> the key to be unwrapped. </param>
		/// <param name="wrappedKeyAlgorithm"> the algorithm associated with the wrapped key. </param>
		/// <param name="wrappedKeyType"> the type of the wrapped key. This must be one of
		/// <code>SECRET_KEY</code>, <code>PRIVATE_KEY</code>, or <code>PUBLIC_KEY</code>. </param>
		/// <returns> the unwrapped key. </returns>
		/// <exception cref="IllegalStateException"> if this cipher is in a wrong state
		/// (e.g., has not been initialized). </exception>
		/// <exception cref="InvalidKeyException"> if <code>wrappedKey</code> does not
		/// represent a wrapped key, or if the algorithm associated with the
		/// wrapped key is different from <code>wrappedKeyAlgorithm</code> 
		/// and/or its key type is different from <code>wrappedKeyType</code>. </exception>
		/// <exception cref="NoSuchAlgorithmException"> - if no installed providers
		/// can create keys for the <code>wrappedKeyAlgorithm</code>. </exception>
		public Key unwrap(byte[] wrappedKey, string wrappedKeyAlgorithm, int wrappedKeyType)
		{
			if (mode != UNWRAP_MODE)
			{
				throw new IllegalStateException("Cipher is not initialised for unwrapping");
			}

			if (wrappedKeyType != SECRET_KEY && wrappedKeyType != PUBLIC_KEY && wrappedKeyType != PRIVATE_KEY)
			{
				throw new IllegalArgumentException("Invalid key type argument");
			}

			if (wrappedKey == null)
			{
				throw new IllegalArgumentException("Null wrappedKey passed");
			}

			if (string.ReferenceEquals(wrappedKeyAlgorithm, null))
			{
				throw new IllegalArgumentException("Null wrappedKeyAlgorithm string passed");
			}

			return cipherSpi.engineUnwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
		}
	}

}