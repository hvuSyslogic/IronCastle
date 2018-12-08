namespace org.bouncycastle.pqc.jcajce.provider.util
{


	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;


	/// <summary>
	/// The AsymmetricBlockCipher class extends CipherSpiExt.
	/// NOTE: Some Ciphers are using Padding. OneAndZeroesPadding is used as default
	/// padding. However padding can still be specified, but mode is not supported;
	/// if you try to instantiate the cipher with something else than "NONE" as mode
	/// NoSuchAlgorithmException is thrown.
	/// </summary>
	public abstract class AsymmetricBlockCipher : CipherSpiExt
	{

		/// <summary>
		/// ParameterSpec used with this cipher
		/// </summary>
		protected internal AlgorithmParameterSpec paramSpec;

		/// <summary>
		/// Internal buffer
		/// </summary>
		protected internal ByteArrayOutputStream buf;

		/// <summary>
		/// The maximum number of bytes the cipher can decrypt.
		/// </summary>
		protected internal int maxPlainTextSize;

		/// <summary>
		/// The maximum number of bytes the cipher can encrypt.
		/// </summary>
		protected internal int cipherTextSize;

		/// <summary>
		/// The AsymmetricBlockCipher() constructor
		/// </summary>
		public AsymmetricBlockCipher()
		{
			buf = new ByteArrayOutputStream();
		}

		/// <summary>
		/// Return the block size (in bytes). Note: although the ciphers extending
		/// this class are not block ciphers, the method was adopted to return the
		/// maximal plaintext and ciphertext sizes for non hybrid ciphers. If the
		/// cipher is hybrid, it returns 0.
		/// </summary>
		/// <returns> if the cipher is not a hybrid one the max plain/cipher text size
		///         is returned, otherwise 0 is returned </returns>
		public sealed override int getBlockSize()
		{
			return opMode == ENCRYPT_MODE ? maxPlainTextSize : cipherTextSize;
		}

		/// <returns> <tt>null</tt> since no initialization vector is used. </returns>
		public sealed override byte[] getIV()
		{
			return null;
		}

		/// <summary>
		/// Return the length in bytes that an output buffer would need to be in
		/// order to hold the result of the next update or doFinal operation, given
		/// the input length <tt>inLen</tt> (in bytes). This call takes into
		/// account any unprocessed (buffered) data from a previous update call, and
		/// padding. The actual output length of the next update() or doFinal() call
		/// may be smaller than the length returned by this method.
		/// <para>
		/// If the input length plus the length of the buffered data exceeds the
		/// maximum length, <tt>0</tt> is returned.
		/// </para> </summary>
		/// <param name="inLen"> the length of the input </param>
		/// <returns> the length of the ciphertext or <tt>0</tt> if the input is too
		///         long. </returns>
		public sealed override int getOutputSize(int inLen)
		{

			int totalLen = inLen + buf.size();

			int maxLen = getBlockSize();

			if (totalLen > maxLen)
			{
				// the length of the input exceeds the maximal supported length
				return 0;
			}

			return maxLen;
		}

		/// <summary>
		/// Returns the parameters used with this cipher.
		/// <para>
		/// The returned parameters may be the same that were used to initialize this
		/// cipher, or may contain the default set of parameters or a set of randomly
		/// generated parameters used by the underlying cipher implementation
		/// (provided that the underlying cipher implementation uses a default set of
		/// parameters or creates new parameters if it needs parameters but was not
		/// initialized with any).
		/// </para>
		/// </summary>
		/// <returns> the parameters used with this cipher, or null if this cipher does
		///         not use any parameters. </returns>
		public sealed override AlgorithmParameterSpec getParameters()
		{
			return paramSpec;
		}

		/// <summary>
		/// Initializes the cipher for encryption by forwarding it to
		/// initEncrypt(Key, FlexiSecureRandom).
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be derived
		/// from the given key, the underlying cipher implementation is supposed to
		/// generate the required parameters itself (using provider-specific default
		/// or random values) if it is being initialized for encryption, and raise an
		/// InvalidKeyException if it is being initialized for decryption. The
		/// generated parameters can be retrieved using engineGetParameters or
		/// engineGetIV (if the parameter is an IV).
		/// </para> </summary>
		/// <param name="key"> the encryption or decryption key. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
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
		/// initEncrypt(Key, FlexiSecureRandom, AlgorithmParameterSpec).
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be derived
		/// from the given key, the underlying cipher implementation is supposed to
		/// generate the required parameters itself (using provider-specific default
		/// or random values) if it is being initialized for encryption, and raise an
		/// InvalidKeyException if it is being initialized for decryption. The
		/// generated parameters can be retrieved using engineGetParameters or
		/// engineGetIV (if the parameter is an IV).
		/// </para> </summary>
		/// <param name="key">    the encryption or decryption key. </param>
		/// <param name="random"> the source of randomness. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
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
		/// Initializes the cipher for encryption by forwarding it to
		/// initEncrypt(Key, FlexiSecureRandom, AlgorithmParameterSpec).
		/// </summary>
		/// <param name="key">    the encryption or decryption key. </param>
		/// <param name="params"> the algorithm parameters. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algortihm parameters are inappropriate for
		/// this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters and params
		/// is null. </exception>
		public void initEncrypt(Key key, AlgorithmParameterSpec @params)
		{
			initEncrypt(key, @params, CryptoServicesRegistrar.getSecureRandom());
		}

		/// <summary>
		/// This method initializes the AsymmetricBlockCipher with a certain key for
		/// data encryption.
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from random.
		/// </para>
		/// </para><para>
		/// Note that when a Cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it
		/// </p>
		/// </summary>
		/// <param name="key">          the key which has to be used to encrypt data. </param>
		/// <param name="secureRandom"> the source of randomness. </param>
		/// <param name="params">       the algorithm parameters. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate for
		/// this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters and params
		/// is null. </exception>
		public sealed override void initEncrypt(Key key, AlgorithmParameterSpec @params, SecureRandom secureRandom)
		{
			opMode = ENCRYPT_MODE;
			initCipherEncrypt(key, @params, secureRandom);
		}

		/// <summary>
		/// Initialize the cipher for decryption by forwarding it to
		/// <seealso cref="#initDecrypt(Key, AlgorithmParameterSpec)"/>.
		/// <para>
		/// If this cipher requires any algorithm parameters that cannot be derived
		/// from the given key, the underlying cipher implementation is supposed to
		/// generate the required parameters itself (using provider-specific default
		/// or random values) if it is being initialized for encryption, and raise an
		/// InvalidKeyException if it is being initialized for decryption. The
		/// generated parameters can be retrieved using engineGetParameters or
		/// engineGetIV (if the parameter is an IV).
		/// </para> </summary>
		/// <param name="key"> the encryption or decryption key. </param>
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
		/// This method initializes the AsymmetricBlockCipher with a certain key for
		/// data decryption.
		/// <para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from random.
		/// </para>
		/// </para><para>
		/// Note that when a Cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it
		/// </p>
		/// </summary>
		/// <param name="key">    the key which has to be used to decrypt data. </param>
		/// <param name="params"> the algorithm parameters. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate for
		/// this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters and params
		/// is null. </exception>
		public sealed override void initDecrypt(Key key, AlgorithmParameterSpec @params)
		{
			opMode = DECRYPT_MODE;
			initCipherDecrypt(key, @params);
		}

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation. This method
		/// just writes the input into an internal buffer.
		/// </summary>
		/// <param name="input"> byte array containing the next part of the input </param>
		/// <param name="inOff"> index in the array where the input starts </param>
		/// <param name="inLen"> length of the input </param>
		/// <returns> a new buffer with the result (always empty) </returns>
		public sealed override byte[] update(byte[] input, int inOff, int inLen)
		{
			if (inLen != 0)
			{
				buf.write(input, inOff, inLen);
			}
			return new byte[0];
		}

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized), processing another data part.
		/// </summary>
		/// <param name="input">  the input buffer </param>
		/// <param name="inOff">  the offset where the input starts </param>
		/// <param name="inLen">  the input length </param>
		/// <param name="output"> the output buffer </param>
		/// <param name="outOff"> the offset where the result is stored </param>
		/// <returns> the length of the output (always 0) </returns>
		public sealed override int update(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{
			update(input, inOff, inLen);
			return 0;
		}

		/// <summary>
		/// Finish a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized).
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inOff"> the offset where the input starts </param>
		/// <param name="inLen"> the input length </param>
		/// <returns> a new buffer with the result </returns>
		/// <exception cref="IllegalBlockSizeException"> if the plaintext or ciphertext size is too large. </exception>
		/// <exception cref="BadPaddingException"> if the ciphertext is invalid. </exception>
		public sealed override byte[] doFinal(byte[] input, int inOff, int inLen)
		{

			checkLength(inLen);
			update(input, inOff, inLen);
			byte[] mBytes = buf.toByteArray();
			buf.reset();

			switch (opMode)
			{
			case ENCRYPT_MODE:
				return messageEncrypt(mBytes);

			case DECRYPT_MODE:
				return messageDecrypt(mBytes);

			default:
				return null;

			}
		}

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
		/// <exception cref="IllegalBlockSizeException"> if the plaintext or ciphertext size is too large. </exception>
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
		/// Since asymmetric block ciphers do not support modes, this method does
		/// nothing.
		/// </summary>
		/// <param name="modeName"> the cipher mode (unused) </param>
		public sealed override void setMode(string modeName)
		{
			// empty
		}

		/// <summary>
		/// Since asymmetric block ciphers do not support padding, this method does
		/// nothing.
		/// </summary>
		/// <param name="paddingName"> the name of the padding scheme (not used) </param>
		public sealed override void setPadding(string paddingName)
		{
			// empty
		}

		/// <summary>
		/// Check if the message length plus the length of the input length can be
		/// en/decrypted. This method uses the specific values
		/// <seealso cref="#maxPlainTextSize"/> and <seealso cref="#cipherTextSize"/> which are set by
		/// the implementations. If the input length plus the length of the internal
		/// buffer is greater than <seealso cref="#maxPlainTextSize"/> for encryption or not
		/// equal to <seealso cref="#cipherTextSize"/> for decryption, an
		/// <seealso cref="IllegalBlockSizeException"/> will be thrown.
		/// </summary>
		/// <param name="inLen"> length of the input to check </param>
		/// <exception cref="IllegalBlockSizeException"> if the input length is invalid. </exception>
		public virtual void checkLength(int inLen)
		{

			int inLength = inLen + buf.size();

			if (opMode == ENCRYPT_MODE)
			{
				if (inLength > maxPlainTextSize)
				{
					throw new IllegalBlockSizeException("The length of the plaintext (" + inLength + " bytes) is not supported by " + "the cipher (max. " + maxPlainTextSize + " bytes).");
				}
			}
			else if (opMode == DECRYPT_MODE)
			{
				if (inLength != cipherTextSize)
				{
					throw new IllegalBlockSizeException("Illegal ciphertext length (expected " + cipherTextSize + " bytes, was " + inLength + " bytes).");
				}
			}

		}

		/// <summary>
		/// Initialize the AsymmetricBlockCipher with a certain key for data
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
		/// Initialize the AsymmetricBlockCipher with a certain key for data
		/// encryption.
		/// </summary>
		/// <param name="key">    the key which has to be used to decrypt data </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters are inappropriate for
		/// initializing this cipher. </exception>
		public abstract void initCipherDecrypt(Key key, AlgorithmParameterSpec @params);

		/// <summary>
		/// Encrypt the message stored in input. The method should also perform an
		/// additional length check.
		/// </summary>
		/// <param name="input"> the message to be encrypted (usually the message length is
		///              less than or equal to maxPlainTextSize) </param>
		/// <returns> the encrypted message (it has length equal to maxCipherTextSize_) </returns>
		/// <exception cref="IllegalBlockSizeException"> if the input is inappropriate for this cipher. </exception>
		/// <exception cref="BadPaddingException"> if the input format is invalid. </exception>
		public abstract byte[] messageEncrypt(byte[] input);

		/// <summary>
		/// Decrypt the ciphertext stored in input. The method should also perform an
		/// additional length check.
		/// </summary>
		/// <param name="input"> the ciphertext to be decrypted (the ciphertext length is
		///              less than or equal to maxCipherTextSize) </param>
		/// <returns> the decrypted message </returns>
		/// <exception cref="IllegalBlockSizeException"> if the input is inappropriate for this cipher. </exception>
		/// <exception cref="BadPaddingException"> if the input format is invalid. </exception>
		public abstract byte[] messageDecrypt(byte[] input);

	}

}