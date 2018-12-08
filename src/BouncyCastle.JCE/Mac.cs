namespace javax.crypto
{

	/// <summary>
	/// This class provides the functionality of a "Message Authentication Code"
	/// (MAC) algorithm.
	/// <para>
	/// A MAC provides a way to check the integrity of information transmitted over
	/// or stored in an unreliable medium, based on a secret key. Typically, message
	/// authentication codes are used between two parties that share a secret
	/// key in order to validate information transmitted between these
	/// parties.
	/// </para>
	/// <para>
	/// A MAC mechanism that is based on cryptographic hash functions is
	/// referred to as HMAC. HMAC can be used with any cryptographic hash function,
	/// e.g., MD5 or SHA-1, in combination with a secret shared key. HMAC is
	/// specified in RFC 2104.
	/// </para>
	/// </summary>
	public class Mac : Cloneable
	{
		internal MacSpi macSpi;
		internal Provider provider;
		internal string algorithm;

		private bool initialised = false;

		/// <summary>
		/// Creates a MAC object.
		/// </summary>
		/// <param name="macSpi"> the delegate </param>
		/// <param name="provider"> the provider </param>
		/// <param name="algorithm"> the algorithm </param>
		public Mac(MacSpi macSpi, Provider provider, string algorithm)
		{
			this.macSpi = macSpi;
			this.provider = provider;
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Returns the algorithm name of this <code>Mac</code> object.
		/// <para>
		/// This is the same name that was specified in one of the
		/// <code>getInstance</code> calls that created this <code>Mac</code> object.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the algorithm name of this <code>Mac</code> object. </returns>
		public string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// Generates an <code>Mac</code> object that implements the
		/// specified MAC algorithm.
		/// If the default provider package provides an implementation of the
		/// requested MAC algorithm, an instance of
		/// <code>Mac</code> containing that implementation is returned.
		/// If the algorithm is not available in the default provider package,
		/// other provider packages are searched.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested MAC algorithm. 
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference
		/// for information about standard algorithm names. </param>
		/// <returns> the new <code>Mac</code> object. </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algorithm is not
		/// available in the default provider package or any of the other provider
		/// packages that were searched. </exception>
		public static Mac getInstance(string algorithm)
		{
			try
			{
				JCEUtil.Implementation imp = JCEUtil.getImplementation("Mac", algorithm, (string) null);

				if (imp == null)
				{
					throw new NoSuchAlgorithmException(algorithm + " not found");
				}

				Mac mac = new Mac((MacSpi)imp.getEngine(), imp.getProvider(), algorithm);

				return mac;
			}
			catch (NoSuchProviderException)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}
		}

		/// <summary>
		/// Generates an <code>Mac</code> object for the specified MAC
		/// algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested MAC algorithm.
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference
		/// for information about standard algorithm names. </param>
		/// <param name="provider"> the name of the provider. </param>
		/// <returns> the new <code>Mac</code> object. </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algorithm is not available from the
		/// specified provider. </exception>
		/// <exception cref="NoSuchProviderException"> if the specified provider has not been configured. </exception>
		public static Mac getInstance(string algorithm, string provider)
		{
			if (string.ReferenceEquals(provider, null))
			{
				throw new IllegalArgumentException("No provider specified to Mac.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("Mac", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			Mac mac = new Mac((MacSpi)imp.getEngine(), imp.getProvider(), algorithm);

			return mac;
		}

		/// <summary>
		/// Generates an <code>Mac</code> object for the specified MAC
		/// algorithm from the specified provider.
		/// </summary>
		/// <param name="algorithm"> the standard name of the requested MAC algorithm.
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference
		/// for information about standard algorithm names. </param>
		/// <param name="provider"> the provider. </param>
		/// <returns> the new <code>Mac</code> object. </returns>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algorithm is not available from the
		/// specified provider. </exception>
		public static Mac getInstance(string algorithm, Provider provider)
		{
			if (provider == null)
			{
				throw new IllegalArgumentException("No provider specified to Mac.getInstance()");
			}

			JCEUtil.Implementation imp = JCEUtil.getImplementation("Mac", algorithm, provider);

			if (imp == null)
			{
				throw new NoSuchAlgorithmException(algorithm + " not found");
			}

			Mac mac = new Mac((MacSpi)imp.getEngine(), imp.getProvider(), algorithm);

			return mac;
		}

		/// <summary>
		/// Returns the provider of this <code>Mac</code> object.
		/// </summary>
		/// <returns> the provider of this <code>Mac</code> object. </returns>
		public Provider getProvider()
		{
			return provider;
		}

		/// <summary>
		/// Returns the length of the MAC in bytes.
		/// </summary>
		/// <returns> the MAC length in bytes. </returns>
		public int getMacLength()
		{
			return macSpi.engineGetMacLength();
		}

		/// <summary>
		/// Initializes this <code>Mac</code> object with the given key.
		/// </summary>
		/// <param name="key"> the key. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this MAC. </exception>
		public void init(Key key)
		{
			try
			{
				macSpi.engineInit(key, null);
				initialised = true;
			}
			catch (InvalidAlgorithmParameterException)
			{
				throw new IllegalArgumentException("underlying mac waon't work without an AlgorithmParameterSpec");
			}
		}

		/// <summary>
		/// Initializes this <code>Mac</code> object with the given key and
		/// algorithm parameters.
		/// </summary>
		/// <param name="key"> the key. </param>
		/// <param name="params"> the algorithm parameters. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this MAC. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate
		/// for this MAC. </exception>
		public void init(Key key, AlgorithmParameterSpec @params)
		{
			macSpi.engineInit(key, @params);
			initialised = true;
		}

		/// <summary>
		/// Processes the given byte.
		/// </summary>
		/// <param name="input"> the input byte to be processed. </param>
		/// <exception cref="IllegalStateException"> if this <code>Mac</code> has not been initialized. </exception>
		public void update(byte input)
		{
			if (!initialised)
			{
				throw new IllegalStateException("MAC not initialised");
			}

			macSpi.engineUpdate(input);
		}

		/// <summary>
		/// Processes the given array of bytes.
		/// </summary>
		/// <param name="input"> the array of bytes to be processed. </param>
		/// <exception cref="IllegalStateException"> if this <code>Mac</code> has not been initialized. </exception>
		public void update(byte[] input)
		{
			if (!initialised)
			{
				throw new IllegalStateException("MAC not initialised");
			}

			if (input == null)
			{
				return;
			}

			macSpi.engineUpdate(input, 0, input.Length);
		}

		/// <summary>
		/// Processes the first <code>len</code> bytes in <code>input</code>,
		/// starting at <code>offset</code> inclusive.
		/// </summary>
		/// <param name="input"> the input buffer. </param>
		/// <param name="offset"> the offset in <code>input</code> where the input starts. </param>
		/// <param name="len"> the number of bytes to process. </param>
		/// <exception cref="IllegalStateException"> if this <code>Mac</code> has not been initialized. </exception>
		public void update(byte[] input, int offset, int len)
		{
			if (!initialised)
			{
				throw new IllegalStateException("MAC not initialised");
			}

			if (input == null)
			{
				throw new IllegalArgumentException("Null input passed");
			}

			if (len < 0 || offset < 0 || len > (input.Length - offset))
			{
				throw new IllegalArgumentException("Bad offset/len");
			}

			if (input.Length == 0)
			{
				return;
			}

			macSpi.engineUpdate(input, offset, len);
		}

		/// <summary>
		/// Finishes the MAC operation.
		/// <para>
		/// A call to this method resets this <code>Mac</code> object to the
		/// state it was in when previously initialized via a call to <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>.
		/// That is, the object is reset and available to generate another MAC from
		/// the same key, if desired, via new calls to <code>update</code> and 
		/// <code>doFinal</code>.     
		/// (In order to reuse this <code>Mac</code> object with a different key,
		/// it must be reinitialized via a call to <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the MAC result. </returns>
		/// <exception cref="IllegalStateException"> if this <code>Mac</code> has not been initialized. </exception>
		public byte[] doFinal()
		{
			if (!initialised)
			{
				throw new IllegalStateException("MAC not initialised");
			}

			return macSpi.engineDoFinal();
		}

		/// <summary>
		/// Finishes the MAC operation.
		/// 
		/// <para>A call to this method resets this <code>Mac</code> object to the
		/// state it was in when previously initialized via a call to
		/// <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>.
		/// That is, the object is reset and available to generate another MAC from
		/// the same key, if desired, via new calls to <code>update</code> and 
		/// <code>doFinal</code>.     
		/// (In order to reuse this <code>Mac</code> object with a different key,
		/// it must be reinitialized via a call to <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>.
		/// </para>
		/// <para>
		/// The MAC result is stored in <code>output</code>, starting at
		/// <code>outOffset</code> inclusive.
		/// 
		/// </para>
		/// </summary>
		/// <param name="output"> the buffer where the MAC result is stored </param>
		/// <param name="outOffset"> the offset in <code>output</code> where the MAC is stored </param>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small to hold the result </exception>
		/// <exception cref="IllegalStateException"> if this <code>Mac</code> has not been initialized. </exception>
		public void doFinal(byte[] output, int outOffset)
		{
			if (!initialised)
			{
				throw new IllegalStateException("MAC not initialised");
			}

			if ((output.Length - outOffset) < macSpi.engineGetMacLength())
			{
				throw new ShortBufferException("buffer to short for MAC output");
			}

			byte[] mac = macSpi.engineDoFinal();

			JavaSystem.arraycopy(mac, 0, output, outOffset, mac.Length);
		}

		/// <summary>
		/// Processes the given array of bytes and finishes the MAC operation.
		/// <para>
		/// A call to this method resets this <code>Mac</code> object to the
		/// state it was in when previously initialized via a call to <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>. That is, the object is reset and
		/// available to generate another MAC from the same key, if desired, via new calls to
		/// <code>update</code> and <code>doFinal</code>.     
		/// (In order to reuse this <code>Mac</code> object with a different key,
		/// it must be reinitialized via a call to <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the MAC result. </returns>
		/// <exception cref="IllegalStateException"> if this <code>Mac</code> has not been initialized. </exception>
		public byte[] doFinal(byte[] input)
		{
			if (!initialised)
			{
				throw new IllegalStateException("MAC not initialised");
			}

			macSpi.engineUpdate(input, 0, input.Length);

			return macSpi.engineDoFinal();
		}

		/// <summary>
		/// Resets this <code>Mac</code> object.
		/// <para>
		/// A call to this method resets this <code>Mac</code> object to the
		/// state it was in when previously initialized via a call to
		/// <code>init(Key)</code> or <code>init(Key, AlgorithmParameterSpec)</code>.
		/// That is, the object is reset and available to generate another MAC from
		/// the same key, if desired, via new calls to <code>update</code> and 
		/// <code>doFinal</code>.     
		/// (In order to reuse this <code>Mac</code> object with a different key,
		/// it must be reinitialized via a call to <code>init(Key)</code> or
		/// <code>init(Key, AlgorithmParameterSpec)</code>.
		/// </para>
		/// </summary>
		public void reset()
		{
			macSpi.engineReset();
		}

		/// <summary>
		/// Returns a clone if the provider implementation is cloneable.
		/// </summary>
		/// <returns> a clone if the provider implementation is cloneable. </returns>
		/// <exception cref="CloneNotSupportedException"> if this is called on a delegate that does
		/// not support <code>Cloneable</code>. </exception>
		public object clone()
		{
			Mac result = new Mac((MacSpi)macSpi.clone(), provider, algorithm);
			result.initialised = initialised;
			return result;
		}
	}

}