using javax.crypto;

namespace org.bouncycastle.pqc.jcajce.provider.util
{



	/// <summary>
	/// The CipherSpiExt class extends CipherSpi.
	/// </summary>
	public abstract class CipherSpiExt : CipherSpi
	{

		/// <summary>
		/// Constant specifying encrypt mode.
		/// </summary>
		public const int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;

		/// <summary>
		/// Constant specifying decrypt mode.
		/// </summary>
		public const int DECRYPT_MODE = Cipher.DECRYPT_MODE;

		/// <summary>
		/// The operation mode for this cipher (<seealso cref="#ENCRYPT_MODE"/> or
		/// <seealso cref="#DECRYPT_MODE"/>).
		/// </summary>
		protected internal int opMode;

		// ****************************************************
		// JCA adapter methods
		// ****************************************************

		/// <summary>
		/// Initialize this cipher object with a proper key and some random seed.
		/// Before a cipher object is ready for data processing, it has to be
		/// initialized according to the desired cryptographic operation, which is
		/// specified by the <tt>opMode</tt> parameter.
		/// <para>
		/// If this cipher (including its underlying mode or padding scheme) requires
		/// any random bytes, it will obtain them from <tt>random</tt>.
		/// </para>
		/// </para><para>
		/// Note: If the mode needs an initialization vector, a blank array is used
		/// in this case. </summary>
		/// <param name="opMode"> the operation mode (<seealso cref="#ENCRYPT_MODE"/> or
		///               <seealso cref="#DECRYPT_MODE"/>) </param>
		/// <param name="key">    the key </param>
		/// <param name="random"> the random seed </param>
		/// <exception cref="java.security.InvalidKeyException"> if the key is inappropriate for initializing this cipher. </exception>
		public sealed override void engineInit(int opMode, Key key, SecureRandom random)
		{

			try
			{
				engineInit(opMode, key, (AlgorithmParameterSpec)null, random);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new InvalidParameterException(e.Message);
			}
		}

		/// <summary>
		/// Initialize this cipher with a key, a set of algorithm parameters, and a
		/// source of randomness. The cipher is initialized for encryption or
		/// decryption, depending on the value of <tt>opMode</tt>.
		/// <para>
		/// If this cipher (including its underlying mode or padding scheme) requires
		/// any random bytes, it will obtain them from <tt>random</tt>. Note that
		/// when a cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it.
		/// </para>
		/// </para><para>
		/// Note: If the mode needs an initialization vector, a try to retrieve it
		/// from the AlgorithmParametersSpec is made.
		/// </p> </summary>
		/// <param name="opMode">    the operation mode (<seealso cref="#ENCRYPT_MODE"/> or
		///                  <seealso cref="#DECRYPT_MODE"/>) </param>
		/// <param name="key">       the key </param>
		/// <param name="algParams"> the algorithm parameters </param>
		/// <param name="random">    the random seed </param>
		/// <exception cref="java.security.InvalidKeyException"> if the key is inappropriate for initializing this block
		/// cipher. </exception>
		/// <exception cref="java.security.InvalidAlgorithmParameterException"> if the parameters are inappropriate for initializing this
		/// block cipher. </exception>
		public sealed override void engineInit(int opMode, Key key, java.security.AlgorithmParameters algParams, SecureRandom random)
		{

			// if algParams are not specified, initialize without them
			if (algParams == null)
			{
				engineInit(opMode, key, random);
				return;
			}

			AlgorithmParameterSpec paramSpec = null;
			// XXX getting AlgorithmParameterSpec from AlgorithmParameters

			engineInit(opMode, key, paramSpec, random);
		}

		/// <summary>
		/// Initialize this cipher with a key, a set of algorithm parameters, and a
		/// source of randomness. The cipher is initialized for one of the following
		/// four operations: encryption, decryption, key wrapping or key unwrapping,
		/// depending on the value of opMode. If this cipher (including its
		/// underlying feedback or padding scheme) requires any random bytes (e.g.,
		/// for parameter generation), it will get them from random. Note that when a
		/// Cipher object is initialized, it loses all previously-acquired state. In
		/// other words, initializing a Cipher is equivalent to creating a new
		/// instance of that Cipher and initializing it.
		/// </summary>
		/// <param name="opMode">   the operation mode (<seealso cref="#ENCRYPT_MODE"/> or
		///                 <seealso cref="#DECRYPT_MODE"/>) </param>
		/// <param name="key">      the encryption key </param>
		/// <param name="params">   the algorithm parameters </param>
		/// <param name="javaRand"> the source of randomness </param>
		/// <exception cref="java.security.InvalidKeyException"> if the given key is inappropriate for initializing this
		/// cipher </exception>
		/// <exception cref="java.security.InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate for
		/// this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters and the
		/// parameters are null. </exception>
		public override void engineInit(int opMode, Key key, AlgorithmParameterSpec @params, SecureRandom javaRand)
		{

			if ((@params != null) && !(@params is AlgorithmParameterSpec))
			{
				throw new InvalidAlgorithmParameterException();
			}

			if ((key == null) || !(key is Key))
			{
				throw new InvalidKeyException();
			}

			this.opMode = opMode;

			if (opMode == ENCRYPT_MODE)
			{
				SecureRandom flexiRand = javaRand;
				initEncrypt((Key)key, (AlgorithmParameterSpec)@params, flexiRand);

			}
			else if (opMode == DECRYPT_MODE)
			{
				initDecrypt((Key)key, (AlgorithmParameterSpec)@params);

			}
		}

		/// <summary>
		/// Return the result of the last step of a multi-step en-/decryption
		/// operation or the result of a single-step en-/decryption operation by
		/// processing the given input data and any remaining buffered data. The data
		/// to be processed is given in an input byte array. Beginning at
		/// inputOffset, only the first inputLen bytes are en-/decrypted, including
		/// any buffered bytes of a previous update operation. If necessary, padding
		/// is performed. The result is returned as a output byte array.
		/// </summary>
		/// <param name="input"> the byte array holding the data to be processed </param>
		/// <param name="inOff"> the offset indicating the start position within the input
		///              byte array </param>
		/// <param name="inLen"> the number of bytes to be processed </param>
		/// <returns> the byte array containing the en-/decrypted data </returns>
		/// <exception cref="javax.crypto.IllegalBlockSizeException"> if the ciphertext length is not a multiple of the
		/// blocklength. </exception>
		/// <exception cref="javax.crypto.BadPaddingException"> if unpadding is not possible. </exception>
		public sealed override byte[] engineDoFinal(byte[] input, int inOff, int inLen)
		{
			return doFinal(input, inOff, inLen);
		}

		/// <summary>
		/// Perform the last step of a multi-step en-/decryption operation or a
		/// single-step en-/decryption operation by processing the given input data
		/// and any remaining buffered data. The data to be processed is given in an
		/// input byte array. Beginning at inputOffset, only the first inputLen bytes
		/// are en-/decrypted, including any buffered bytes of a previous update
		/// operation. If necessary, padding is performed. The result is stored in
		/// the given output byte array, beginning at outputOffset. The number of
		/// bytes stored in this byte array are returned.
		/// </summary>
		/// <param name="input">  the byte array holding the data to be processed </param>
		/// <param name="inOff">  the offset indicating the start position within the input
		///               byte array </param>
		/// <param name="inLen">  the number of bytes to be processed </param>
		/// <param name="output"> the byte array for holding the result </param>
		/// <param name="outOff"> the offset indicating the start position within the output
		///               byte array to which the en/decrypted data is written </param>
		/// <returns> the number of bytes stored in the output byte array </returns>
		/// <exception cref="javax.crypto.ShortBufferException"> if the output buffer is too short to hold the output. </exception>
		/// <exception cref="javax.crypto.IllegalBlockSizeException"> if the ciphertext length is not a multiple of the
		/// blocklength. </exception>
		/// <exception cref="javax.crypto.BadPaddingException"> if unpadding is not possible. </exception>
		public sealed override int engineDoFinal(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{
			return doFinal(input, inOff, inLen, output, outOff);
		}

		/// <returns> the block size (in bytes), or 0 if the underlying algorithm is
		///         not a block cipher </returns>
		public sealed override int engineGetBlockSize()
		{
			return getBlockSize();
		}

		/// <summary>
		/// Return the key size of the given key object in bits.
		/// </summary>
		/// <param name="key"> the key object </param>
		/// <returns> the key size in bits of the given key object </returns>
		/// <exception cref="java.security.InvalidKeyException"> if key is invalid. </exception>
		public sealed override int engineGetKeySize(Key key)
		{
			if (!(key is Key))
			{
				throw new InvalidKeyException("Unsupported key.");
			}
			return getKeySize((Key)key);
		}

		/// <summary>
		/// Return the initialization vector. This is useful in the context of
		/// password-based encryption or decryption, where the IV is derived from a
		/// user-provided passphrase.
		/// </summary>
		/// <returns> the initialization vector in a new buffer, or <tt>null</tt> if
		///         the underlying algorithm does not use an IV, or if the IV has not
		///         yet been set. </returns>
		public sealed override byte[] engineGetIV()
		{
			return getIV();
		}

		/// <summary>
		/// Return the length in bytes that an output buffer would need to be in
		/// order to hold the result of the next update or doFinal operation, given
		/// the input length inputLen (in bytes).
		/// <para>
		/// This call takes into account any unprocessed (buffered) data from a
		/// previous update call, and padding.
		/// </para>
		/// </para><para>
		/// The actual output length of the next update or doFinal call may be
		/// smaller than the length returned by this method.
		/// </p> </summary>
		/// <param name="inLen"> the input length (in bytes) </param>
		/// <returns> the required output buffer size (in bytes) </returns>
		public sealed override int engineGetOutputSize(int inLen)
		{
			return getOutputSize(inLen);
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
		/// </para> </summary>
		/// <returns> the parameters used with this cipher, or null if this cipher does
		///         not use any parameters. </returns>
		public sealed override java.security.AlgorithmParameters engineGetParameters()
		{
			// TODO
			return null;
		}

		/// <summary>
		/// Set the mode of this cipher.
		/// </summary>
		/// <param name="modeName"> the cipher mode </param>
		/// <exception cref="java.security.NoSuchAlgorithmException"> if neither the mode with the given name nor the default
		/// mode can be found </exception>
		public sealed override void engineSetMode(string modeName)
		{
			setMode(modeName);
		}

		/// <summary>
		/// Set the padding scheme of this cipher.
		/// </summary>
		/// <param name="paddingName"> the padding scheme </param>
		/// <exception cref="javax.crypto.NoSuchPaddingException"> if the requested padding scheme cannot be found. </exception>
		public sealed override void engineSetPadding(string paddingName)
		{
			setPadding(paddingName);
		}

		/// <summary>
		/// Return the result of the next step of a multi-step en-/decryption
		/// operation. The data to be processed is given in an input byte array.
		/// Beginning at inputOffset, only the first inputLen bytes are
		/// en-/decrypted. The result is returned as a byte array.
		/// </summary>
		/// <param name="input"> the byte array holding the data to be processed </param>
		/// <param name="inOff"> the offset indicating the start position within the input
		///              byte array </param>
		/// <param name="inLen"> the number of bytes to be processed </param>
		/// <returns> the byte array containing the en-/decrypted data </returns>
		public sealed override byte[] engineUpdate(byte[] input, int inOff, int inLen)
		{
			return update(input, inOff, inLen);
		}

		/// <summary>
		/// Perform the next step of a multi-step en-/decryption operation. The data
		/// to be processed is given in an input byte array. Beginning at
		/// inputOffset, only the first inputLen bytes are en-/decrypted. The result
		/// is stored in the given output byte array, beginning at outputOffset. The
		/// number of bytes stored in this output byte array are returned.
		/// </summary>
		/// <param name="input">  the byte array holding the data to be processed </param>
		/// <param name="inOff">  the offset indicating the start position within the input
		///               byte array </param>
		/// <param name="inLen">  the number of bytes to be processed </param>
		/// <param name="output"> the byte array for holding the result </param>
		/// <param name="outOff"> the offset indicating the start position within the output
		///               byte array to which the en-/decrypted data is written </param>
		/// <returns> the number of bytes that are stored in the output byte array </returns>
		/// <exception cref="javax.crypto.ShortBufferException"> if the output buffer is too short to hold the output. </exception>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: protected final int engineUpdate(final byte[] input, final int inOff, final int inLen, byte[] output, final int outOff) throws javax.crypto.ShortBufferException
		public sealed override int engineUpdate(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{
			return update(input, inOff, inLen, output, outOff);
		}

		/// <summary>
		/// Initialize this cipher with a key, a set of algorithm parameters, and a
		/// source of randomness for encryption.
		/// <para>
		/// If this cipher requires any algorithm parameters and paramSpec is null,
		/// the underlying cipher implementation is supposed to generate the required
		/// parameters itself (using provider-specific default or random values) if
		/// it is being initialized for encryption, and raise an
		/// InvalidAlgorithmParameterException if it is being initialized for
		/// decryption. The generated parameters can be retrieved using
		/// engineGetParameters or engineGetIV (if the parameter is an IV).
		/// </para>
		/// </para><para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from random.
		/// </para><para>
		/// Note that when a cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it.
		/// </summary>
		/// <param name="key">          the encryption key </param>
		/// <param name="cipherParams"> the cipher parameters </param>
		/// <param name="random">       the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// block cipher. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the parameters are inappropriate for initializing this
		/// block cipher. </exception>
		public abstract void initEncrypt(Key key, AlgorithmParameterSpec cipherParams, SecureRandom random);

		/// <summary>
		/// Initialize this cipher with a key, a set of algorithm parameters, and a
		/// source of randomness for decryption.
		/// <para>
		/// If this cipher requires any algorithm parameters and paramSpec is null,
		/// the underlying cipher implementation is supposed to generate the required
		/// parameters itself (using provider-specific default or random values) if
		/// it is being initialized for encryption, and throw an
		/// <seealso cref="InvalidAlgorithmParameterException"/> if it is being initialized for
		/// decryption. The generated parameters can be retrieved using
		/// engineGetParameters or engineGetIV (if the parameter is an IV).
		/// </para>
		/// </para><para>
		/// If this cipher (including its underlying feedback or padding scheme)
		/// requires any random bytes (e.g., for parameter generation), it will get
		/// them from random.
		/// </para><para>
		/// Note that when a cipher object is initialized, it loses all
		/// previously-acquired state. In other words, initializing a Cipher is
		/// equivalent to creating a new instance of that Cipher and initializing it.
		/// </summary>
		/// <param name="key">          the encryption key </param>
		/// <param name="cipherParams"> the cipher parameters </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this
		/// block cipher. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the parameters are inappropriate for initializing this
		/// block cipher. </exception>
		public abstract void initDecrypt(Key key, AlgorithmParameterSpec cipherParams);

		/// <returns> the name of this cipher </returns>
		public abstract string getName();

		/// <returns> the block size (in bytes), or 0 if the underlying algorithm is
		///         not a block cipher </returns>
		public abstract int getBlockSize();

		/// <summary>
		/// Returns the length in bytes that an output buffer would need to be in
		/// order to hold the result of the next update or doFinal operation, given
		/// the input length inputLen (in bytes).
		/// <para>
		/// This call takes into account any unprocessed (buffered) data from a
		/// previous update call, and padding.
		/// </para>
		/// </para><para>
		/// The actual output length of the next update or doFinal call may be
		/// smaller than the length returned by this method.
		/// </summary>
		/// <param name="inputLen"> the input length (in bytes) </param>
		/// <returns> the required output buffer size (in bytes) </returns>
		public abstract int getOutputSize(int inputLen);

		/// <summary>
		/// Return the key size of the given key object in bits.
		/// </summary>
		/// <param name="key"> the key object </param>
		/// <returns> the key size in bits of the given key object </returns>
		/// <exception cref="InvalidKeyException"> if key is invalid. </exception>
		public abstract int getKeySize(Key key);

		/// <summary>
		/// Returns the parameters used with this cipher.
		/// <para>
		/// The returned parameters may be the same that were used to initialize this
		/// cipher, or may contain the default set of parameters or a set of randomly
		/// generated parameters used by the underlying cipher implementation
		/// (provided that the underlying cipher implementation uses a default set of
		/// parameters or creates new parameters if it needs parameters but was not
		/// initialized with any).
		/// 
		/// </para>
		/// </summary>
		/// <returns> the parameters used with this cipher, or null if this cipher does
		///         not use any parameters. </returns>
		public abstract AlgorithmParameterSpec getParameters();

		/// <summary>
		/// Return the initialization vector. This is useful in the context of
		/// password-based encryption or decryption, where the IV is derived from a
		/// user-provided passphrase.
		/// </summary>
		/// <returns> the initialization vector in a new buffer, or <tt>null</tt> if
		///         the underlying algorithm does not use an IV, or if the IV has not
		///         yet been set. </returns>
		public abstract byte[] getIV();

		/// <summary>
		/// Set the mode of this cipher.
		/// </summary>
		/// <param name="mode"> the cipher mode </param>
		/// <exception cref="NoSuchAlgorithmException"> if the requested mode cannot be found. </exception>
		public abstract void setMode(string mode);

		/// <summary>
		/// Set the padding mechanism of this cipher.
		/// </summary>
		/// <param name="padding"> the padding mechanism </param>
		/// <exception cref="NoSuchPaddingException"> if the requested padding scheme cannot be found. </exception>
		public abstract void setPadding(string padding);

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized), processing another data part.
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <returns> a new buffer with the result (maybe an empty byte array) </returns>
		public byte[] update(byte[] input)
		{
			return update(input, 0, input.Length);
		}

		/// <summary>
		/// Continue a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized), processing another data part.
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inOff"> the offset where the input starts </param>
		/// <param name="inLen"> the input length </param>
		/// <returns> a new buffer with the result (maybe an empty byte array) </returns>
		public abstract byte[] update(byte[] input, int inOff, int inLen);

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
		public abstract int update(byte[] input, int inOff, int inLen, byte[] output, int outOff);

		/// <summary>
		/// Finish a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized).
		/// </summary>
		/// <returns> a new buffer with the result </returns>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher and the total input
		/// length is not a multiple of the block size (for
		/// encryption when no padding is used or for decryption). </exception>
		/// <exception cref="BadPaddingException"> if this cipher is a block cipher and unpadding fails. </exception>
		public byte[] doFinal()
		{
			return doFinal(null, 0, 0);
		}

		/// <summary>
		/// Finish a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized).
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <returns> a new buffer with the result </returns>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher and the total input
		/// length is not a multiple of the block size (for
		/// encryption when no padding is used or for decryption). </exception>
		/// <exception cref="BadPaddingException"> if this cipher is a block cipher and unpadding fails. </exception>
		public byte[] doFinal(byte[] input)
		{
			return doFinal(input, 0, input.Length);
		}

		/// <summary>
		/// Finish a multiple-part encryption or decryption operation (depending on
		/// how this cipher was initialized).
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inOff"> the offset where the input starts </param>
		/// <param name="inLen"> the input length </param>
		/// <returns> a new buffer with the result </returns>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher and the total input
		/// length is not a multiple of the block size (for
		/// encryption when no padding is used or for decryption). </exception>
		/// <exception cref="BadPaddingException"> if this cipher is a block cipher and unpadding fails. </exception>
		public abstract byte[] doFinal(byte[] input, int inOff, int inLen);

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
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher and the total input
		/// length is not a multiple of the block size (for
		/// encryption when no padding is used or for decryption). </exception>
		/// <exception cref="BadPaddingException"> if this cipher is a block cipher and unpadding fails. </exception>
		public abstract int doFinal(byte[] input, int inOff, int inLen, byte[] output, int outOff);

	}

}