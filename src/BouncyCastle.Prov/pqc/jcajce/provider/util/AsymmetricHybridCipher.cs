namespace org.bouncycastle.pqc.jcajce.provider.util
{


	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;

	/// <summary>
	/// The AsymmetricHybridCipher class extends CipherSpiExt.
	/// NOTE: Some Ciphers are using Padding. OneAndZeroesPadding is used as default
	/// padding. However padding can still be specified, but mode is not supported;
	/// if you try to instantiate the cipher with something else than "NONE" as mode,
	/// NoSuchAlgorithmException is thrown.
	/// </summary>
	public abstract class AsymmetricHybridCipher : CipherSpiExt
	{

		/// <summary>
		/// ParameterSpec used with this cipher
		/// </summary>
		protected internal AlgorithmParameterSpec paramSpec;

		/// <summary>
		/// Since asymmetric hybrid ciphers do not support modes, this method does
		/// nothing.
		/// </summary>
		/// <param name="modeName"> the cipher mode (unused) </param>
		public sealed override void setMode(string modeName)
		{
			// empty
		}

		/// <summary>
		/// Since asymmetric hybrid ciphers do not support padding, this method does
		/// nothing.
		/// </summary>
		/// <param name="paddingName"> the name of the padding scheme (not used) </param>
		public sealed override void setPadding(string paddingName)
		{
			// empty
		}

		/// <returns> <tt>null</tt> since no initialization vector is used. </returns>
		public sealed override byte[] getIV()
		{
			return null;
		}

		/// <returns> 0 since the implementing algorithms are not block ciphers </returns>
		public sealed override int getBlockSize()
		{
			return 0;
		}

		/// <summary>
		/// Return the parameters used with this cipher.
		/// <para>
		/// The returned parameters may be the same that were used to initialize this
		/// cipher, or may contain the default set of parameters or a set of randomly
		/// generated parameters used by the underlying cipher implementation
		/// (provided that the underlying cipher implementation uses a default set of
		/// parameters or creates new parameters if it needs parameters but was not
		/// initialized with any).
		/// </para> </summary>
		/// <returns> the parameters used with this cipher, or <tt>null</tt> if this
		///         cipher does not use any parameters. </returns>
		public sealed override AlgorithmParameterSpec getParameters()
		{
			return paramSpec;
		}

		/// <summary>
		/// Return the length in bytes that an output buffer would need to be in
		/// order to hold the result of the next update or doFinal operation, given
		/// the input length <tt>inLen</tt> (in bytes). This call takes into
		/// account any unprocessed (buffered) data from a previous update call, and
		/// padding. The actual output length of the next update() or doFinal() call
		/// may be smaller than the length returned by this method.
		/// </summary>
		/// <param name="inLen"> the length of the input </param>
		/// <returns> the length of the output of the next <tt>update()</tt> or
		///         <tt>doFinal()</tt> call </returns>
		public sealed override int getOutputSize(int inLen)
		{
			return opMode == ENCRYPT_MODE ? encryptOutputSize(inLen) : decryptOutputSize(inLen);
		}

		/// <summary>
		/// Initialize the cipher for encryption by forwarding it to
		/// <seealso cref="#initEncrypt(Key, AlgorithmParameterSpec, SecureRandom)"/>.
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be derived
		/// from the given key, the underlying cipher implementation is supposed to
		/// generate the required parameters itself (using provider-specific default
		/// or random values) if it is being initialized for encryption, and raise an
		/// InvalidKeyException if it is being initialized for decryption. The
		/// generated parameters can be retrieved using <seealso cref="#getParameters()"/>.
		/// </para> </summary>
		/// <param name="key"> the encryption key </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
		/// <exception cref="InvalidParameterException"> if this cipher needs algorithm parameters for
		/// initialization and cannot generate parameters itself. </exception>
		public void initEncrypt(Key key)
		{
			try
			{
				initEncrypt(key, null, CryptoServicesRegistrar.getSecureRandom());
			}
			catch (InvalidAlgorithmParameterException)
			{
				throw new InvalidParameterException("This cipher needs algorithm parameters for initialization (cannot be null).");
			}
		}

		/// <summary>
		/// Initialize this cipher for encryption by forwarding it to
		/// <seealso cref="#initEncrypt(Key, AlgorithmParameterSpec, SecureRandom)"/>.
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be derived
		/// from the given key, the underlying cipher implementation is supposed to
		/// generate the required parameters itself (using provider-specific default
		/// or random values) if it is being initialized for encryption, and raise an
		/// InvalidKeyException if it is being initialized for decryption. The
		/// generated parameters can be retrieved using <seealso cref="#getParameters()"/>.
		/// </para> </summary>
		/// <param name="key">    the encryption key </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
		/// <exception cref="InvalidParameterException"> if this cipher needs algorithm parameters for
		/// initialization and cannot generate parameters itself. </exception>
		public void initEncrypt(Key key, SecureRandom random)
		{
			try
			{
				initEncrypt(key, null, random);
			}
			catch (InvalidAlgorithmParameterException)
			{
				throw new InvalidParameterException("This cipher needs algorithm parameters for initialization (cannot be null).");
			}
		}

		/// <summary>
		/// Initialize the cipher for encryption by forwarding it to initEncrypt(Key,
		/// FlexiSecureRandom, AlgorithmParameterSpec).
		/// </summary>
		/// <param name="key">    the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate for
		/// this cipher, or if this cipher is initialized with
		/// <tt>null</tt> parameters and cannot generate parameters
		/// itself. </exception>
		public void initEncrypt(Key key, AlgorithmParameterSpec @params)
		{
			initEncrypt(key, @params, CryptoServicesRegistrar.getSecureRandom());
		}

		/// <summary>
		/// Initialize the cipher with a certain key for data encryption.
		/// <para>
		/// If this cipher requires any random bytes (e.g., for parameter
		/// generation), it will get them from <tt>random</tt>.
		/// </para>
		/// </para><para>
		/// Note that when a Cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it.
		/// </p> </summary>
		/// <param name="key">    the encryption key </param>
		/// <param name="random"> the source of randomness </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate for
		/// this cipher, or if this cipher is initialized with
		/// <tt>null</tt> parameters and cannot generate parameters
		/// itself. </exception>
		public sealed override void initEncrypt(Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			opMode = ENCRYPT_MODE;
			initCipherEncrypt(key, @params, random);
		}

		/// <summary>
		/// Initialize the cipher for decryption by forwarding it to initDecrypt(Key,
		/// FlexiSecureRandom).
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be derived
		/// from the given key, the underlying cipher implementation is supposed to
		/// generate the required parameters itself (using provider-specific default
		/// or random values) if it is being initialized for encryption, and raise an
		/// InvalidKeyException if it is being initialized for decryption. The
		/// generated parameters can be retrieved using <seealso cref="#getParameters()"/>.
		/// </para> </summary>
		/// <param name="key"> the decryption key </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
		public void initDecrypt(Key key)
		{
			try
			{
				initDecrypt(key, null);
			}
			catch (InvalidAlgorithmParameterException)
			{
				throw new InvalidParameterException("This cipher needs algorithm parameters for initialization (cannot be null).");
			}
		}

		/// <summary>
		/// Initialize the cipher with a certain key for data decryption.
		/// <para>
		/// If this cipher requires any random bytes (e.g., for parameter
		/// generation), it will get them from <tt>random</tt>.
		/// </para>
		/// </para><para>
		/// Note that when a Cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it
		/// </p> </summary>
		/// <param name="key">    the decryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate for
		/// this cipher, or if this cipher is initialized with
		/// <tt>null</tt> parameters and cannot generate parameters
		/// itself. </exception>
		public sealed override void initDecrypt(Key key, AlgorithmParameterSpec @params)
		{
			opMode = DECRYPT_MODE;
			initCipherDecrypt(key, @params);
		}

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized), processing another data part.
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inOff"> the offset where the input starts </param>
		/// <param name="inLen"> the input length </param>
		/// <returns> a new buffer with the result (maybe an empty byte array) </returns>
		public override abstract byte[] update(byte[] input, int inOff, int inLen);

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized), processing another data part.
		/// </summary>
		/// <param name="input">  the input buffer </param>
		/// <param name="inOff">  the offset where the input starts </param>
		/// <param name="inLen">  the input length </param>
		/// <param name="output"> the output buffer </param>
		/// <param name="outOff"> the offset where the result is stored </param>
		/// <returns> the length of the output </returns>
		/// <exception cref="ShortBufferException"> if the output buffer is too small to hold the result. </exception>
		public sealed override int update(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{
			if (output.Length < getOutputSize(inLen))
			{
				throw new ShortBufferException("output");
			}
			byte[] @out = update(input, inOff, inLen);
			JavaSystem.arraycopy(@out, 0, output, outOff, @out.Length);
			return @out.Length;
		}

		/// <summary>
		/// Finish a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized).
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inOff"> the offset where the input starts </param>
		/// <param name="inLen"> the input length </param>
		/// <returns> a new buffer with the result </returns>
		/// <exception cref="BadPaddingException"> if the ciphertext is invalid. </exception>
		public override abstract byte[] doFinal(byte[] input, int inOff, int inLen);

		/// <summary>
		/// Finish a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized).
		/// </summary>
		/// <param name="input">  the input buffer </param>
		/// <param name="inOff">  the offset where the input starts </param>
		/// <param name="inLen">  the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <param name="outOff"> the offset where the result is stored </param>
		/// <returns> the output length </returns>
		/// <exception cref="ShortBufferException"> if the output buffer is too small to hold the result. </exception>
		/// <exception cref="BadPaddingException"> if the ciphertext is invalid. </exception>
		public sealed override int doFinal(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{

			if (output.Length < getOutputSize(inLen))
			{
				throw new ShortBufferException("Output buffer too short.");
			}
			byte[] @out = doFinal(input, inOff, inLen);
			JavaSystem.arraycopy(@out, 0, output, outOff, @out.Length);
			return @out.Length;
		}

		/// <summary>
		/// Compute the output size of an update() or doFinal() operation of a hybrid
		/// asymmetric cipher in encryption mode when given input of the specified
		/// length.
		/// </summary>
		/// <param name="inLen"> the length of the input </param>
		/// <returns> the output size </returns>
		public abstract int encryptOutputSize(int inLen);

		/// <summary>
		/// Compute the output size of an update() or doFinal() operation of a hybrid
		/// asymmetric cipher in decryption mode when given input of the specified
		/// length.
		/// </summary>
		/// <param name="inLen"> the length of the input </param>
		/// <returns> the output size </returns>
		public abstract int decryptOutputSize(int inLen);

		/// <summary>
		/// Initialize the AsymmetricHybridCipher with a certain key for data
		/// encryption.
		/// </summary>
		/// <param name="key">    the key which has to be used to encrypt data </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <param name="sr">     the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters are inappropriate for
		/// initializing this cipher. </exception>
		public abstract void initCipherEncrypt(Key key, AlgorithmParameterSpec @params, SecureRandom sr);

		/// <summary>
		/// Initialize the AsymmetricHybridCipher with a certain key for data
		/// encryption.
		/// </summary>
		/// <param name="key">    the key which has to be used to decrypt data </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters are inappropriate for
		/// initializing this cipher. </exception>
		public abstract void initCipherDecrypt(Key key, AlgorithmParameterSpec @params);

	}

}