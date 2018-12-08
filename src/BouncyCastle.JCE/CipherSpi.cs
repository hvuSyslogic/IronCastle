namespace javax.crypto
{

	/// <summary>
	/// This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
	/// for the <code>Cipher</code> class.
	/// All the abstract methods in this class must be implemented by each 
	/// cryptographic service provider who wishes to supply the implementation
	/// of a particular cipher algorithm.
	/// <para>
	/// In order to create an instance of <code>Cipher</code>, which
	/// encapsulates an instance of this <code>CipherSpi</code> class, an
	/// application calls one of the
	/// <a href = "Cipher.html#getInstance(java.lang.String)">getInstance</a>
	/// factory methods of the
	/// <a href = "Cipher.html">Cipher</a> engine class and specifies the requested
	/// <i>transformation</i>.
	/// Optionally, the application may also specify the name of a provider.
	/// </para>
	/// <para>
	/// A <i>transformation</i> is a string that describes the operation (or
	/// set of operations) to be performed on the given input, to produce some
	/// output. A transformation always includes the name of a cryptographic
	/// algorithm (e.g., <i>DES</i>), and may be followed by a feedback mode and
	/// padding scheme.
	/// </para>
	/// <para>
	/// A transformation is of the form:
	/// </para>
	/// <para>
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
	/// 
	/// </para>
	/// <para>A provider may supply a separate class for each combination
	/// of <i>algorithm/mode/padding</i>, or may decide to provide more generic
	/// classes representing sub-transformations corresponding to
	/// <i>algorithm</i> or <i>algorithm/mode</i> or <i>algorithm//padding</i>
	/// (note the double slashes),
	/// in which case the requested mode and/or padding are set automatically by
	/// the <code>getInstance</code> methods of <code>Cipher</code>, which invoke
	/// the <a href = "#engineSetMode(java.lang.String)">engineSetMode</a> and
	/// <a href = "#engineSetPadding(java.lang.String)">engineSetPadding</a>
	/// methods of the provider's subclass of <code>CipherSpi</code>.
	/// 
	/// </para>
	/// <para>A <code>Cipher</code> property in a provider master class may have one of
	/// the following formats:
	/// 
	/// <ul>
	/// 
	/// <li>
	/// <pre>
	///     // provider's subclass of "CipherSpi" implements "algName" with
	///     // pluggable mode and padding
	///     <code>Cipher.</code><i>algName</i>
	/// </pre>
	/// 
	/// <li>
	/// <pre>
	///     // provider's subclass of "CipherSpi" implements "algName" in the
	///     // specified "mode", with pluggable padding
	///     <code>Cipher.</code><i>algName/mode</i>
	/// </pre>
	/// 
	/// <li>
	/// <pre>
	///    // provider's subclass of "CipherSpi" implements "algName" with the
	///    // specified "padding", with pluggable mode
	///    <code>Cipher.</code><i>algName//padding</i>
	/// </pre>
	/// 
	/// <li>
	/// <pre>
	///    // provider's subclass of "CipherSpi" implements "algName" with the
	///    // specified "mode" and "padding"
	///    <code>Cipher.</code><i>algName/mode/padding</i>
	/// </pre>
	/// 
	/// </ul>
	/// 
	/// </para>
	/// <para>For example, a provider may supply a subclass of <code>CipherSpi</code>
	/// that implements <i>DES/ECB/PKCS5Padding</i>, one that implements
	/// <i>DES/CBC/PKCS5Padding</i>, one that implements
	/// <i>DES/CFB/PKCS5Padding</i>, and yet another one that implements
	/// <i>DES/OFB/PKCS5Padding</i>. That provider would have the following
	/// </para>
	/// <code>Cipher</code> properties in its master class:<para>
	/// 
	/// <ul>
	/// 
	/// <li>
	/// <pre>
	///    <code>Cipher.</code><i>DES/ECB/PKCS5Padding</i>
	/// </pre>
	/// 
	/// <li>
	/// <pre>
	///    <code>Cipher.</code><i>DES/CBC/PKCS5Padding</i>
	/// </pre>
	/// 
	/// <li>
	/// <pre>
	///    <code>Cipher.</code><i>DES/CFB/PKCS5Padding</i>
	/// </pre>
	/// 
	/// <li>
	/// <pre>
	///    <code>Cipher.</code><i>DES/OFB/PKCS5Padding</i>
	/// </pre>
	/// 
	/// </ul>
	/// 
	/// </para>
	/// <para>Another provider may implement a class for each of the above modes
	/// (i.e., one class for <i>ECB</i>, one for <i>CBC</i>, one for <i>CFB</i>,
	/// and one for <i>OFB</i>), one class for <i>PKCS5Padding</i>,
	/// and a generic <i>DES</i> class that subclasses from <code>CipherSpi</code>.
	/// That provider would have the following
	/// </para>
	/// <code>Cipher</code> properties in its master class:<para>
	/// 
	/// <ul>
	/// 
	/// <li>
	/// <pre>
	///    <code>Cipher.</code><i>DES</i>
	/// </pre>
	/// 
	/// </ul>
	/// 
	/// </para>
	/// <para>The <code>getInstance</code> factory method of the <code>Cipher</code>
	/// engine class follows these rules in order to instantiate a provider's
	/// implementation of <code>CipherSpi</code> for a
	/// transformation of the form "<i>algorithm</i>":
	/// 
	/// <ol>
	/// <li>
	/// Check if the provider has registered a subclass of <code>CipherSpi</code>
	/// for the specified "<i>algorithm</i>".
	/// </para>
	/// <para>If the answer is YES, instantiate this
	/// class, for whose mode and padding scheme default values (as supplied by
	/// the provider) are used.
	/// </para>
	/// <para>If the answer is NO, throw a <code>NoSuchAlgorithmException</code>
	/// exception.
	/// </ol>
	/// 
	/// </para>
	/// <para>The <code>getInstance</code> factory method of the <code>Cipher</code>
	/// engine class follows these rules in order to instantiate a provider's
	/// implementation of <code>CipherSpi</code> for a
	/// transformation of the form "<i>algorithm/mode/padding</i>":
	/// 
	/// <ol>
	/// <li>
	/// Check if the provider has registered a subclass of <code>CipherSpi</code>
	/// for the specified "<i>algorithm/mode/padding</i>" transformation.
	/// </para>
	/// <para>If the answer is YES, instantiate it.
	/// </para>
	/// <para>If the answer is NO, go to the next step.<p>
	/// <li>
	/// Check if the provider has registered a subclass of <code>CipherSpi</code>
	/// for the sub-transformation "<i>algorithm/mode</i>".
	/// </para>
	/// <para>If the answer is YES, instantiate it, and call
	/// <code>engineSetPadding(<i>padding</i>)</code> on the new instance.
	/// </para>
	/// <para>If the answer is NO, go to the next step.<p>
	/// <li>
	/// Check if the provider has registered a subclass of <code>CipherSpi</code>
	/// for the sub-transformation "<i>algorithm//padding</i>" (note the double
	/// slashes).
	/// </para>
	/// <para>If the answer is YES, instantiate it, and call
	/// <code>engineSetMode(<i>mode</i>)</code> on the new instance.
	/// </para>
	/// <para>If the answer is NO, go to the next step.<p>
	/// <li>
	/// Check if the provider has registered a subclass of <code>CipherSpi</code>
	/// for the sub-transformation "<i>algorithm</i>".
	/// </para>
	/// <para>If the answer is YES, instantiate it, and call
	/// <code>engineSetMode(<i>mode</i>)</code> and
	/// <code>engineSetPadding(<i>padding</i>)</code> on the new instance.
	/// </para>
	/// <para>If the answer is NO, throw a <code>NoSuchAlgorithmException</code>
	/// exception.
	/// </ol>
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= KeyGenerator </seealso>
	/// <seealso cref= SecretKey </seealso>
	public abstract class CipherSpi
	{
		public CipherSpi()
		{
		}

		/// <summary>
		/// Sets the mode of this cipher.
		/// </summary>
		/// <param name="mode"> the cipher mode </param>
		/// <exception cref="NoSuchAlgorithmException"> if the requested cipher mode does not exist </exception>
		public abstract void engineSetMode(string mode);

		/// <summary>
		/// Sets the padding mechanism of this cipher.
		/// </summary>
		/// <param name="padding"> the padding mechanism </param>
		/// <exception cref="NoSuchPaddingException"> if the requested padding mechanism does not exist </exception>
		public abstract void engineSetPadding(string padding);

		/// <summary>
		/// Returns the block size (in bytes).
		/// </summary>
		/// <returns> the block size (in bytes), or 0 if the underlying algorithm is not a block cipher </returns>
		public abstract int engineGetBlockSize();

		/// <summary>
		/// Returns the length in bytes that an output buffer would
		/// need to be in order to hold the result of the next <code>update</code>
		/// or <code>doFinal</code> operation, given the input length
		/// <code>inputLen</code> (in bytes).
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
		public abstract int engineGetOutputSize(int inputLen);

		/// <summary>
		/// Returns the initialization vector (IV) in a new buffer. 
		/// <para>
		/// This is useful in the context of password-based encryption or
		/// decryption, where the IV is derived from a user-provided passphrase.
		/// 
		/// </para>
		/// </summary>
		/// <returns> the initialization vector in a new buffer, or null if the
		/// underlying algorithm does not use an IV, or if the IV has not yet
		/// been set. </returns>
		public abstract byte[] engineGetIV();

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
		public abstract AlgorithmParameters engineGetParameters();

		/// <summary>
		/// Initializes this cipher with a key and a source
		/// of randomness.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or key unwrapping, depending on
		/// the value of <code>opmode</code>.
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
		/// 
		/// </para>
		/// <para>Note that when a Cipher object is initialized, it loses all 
		/// previously-acquired state. In other words, initializing a Cipher is 
		/// equivalent to creating a new instance of that Cipher and initializing 
		/// it.
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of
		/// the following:
		/// <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for
		/// initializing this cipher, or if this cipher is being initialized for
		/// decryption and requires algorithm parameters that cannot be
		/// determined from the given key. </exception>
		public abstract void engineInit(int opmode, Key key, SecureRandom random);

		/// <summary>
		/// Initializes this cipher with a key, a set of
		/// algorithm parameters, and a source of randomness.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or key unwrapping, depending on
		/// the value of <code>opmode</code>.
		/// </para>
		/// <para>
		/// If this cipher requires any algorithm parameters and
		///  <code>params</code> is null, the underlying cipher implementation is
		/// supposed to generate the required parameters itself (using
		/// provider-specific default or random values) if it is being
		/// initialized for encryption or key wrapping, and raise an
		/// <code>InvalidAlgorithmParameterException</code> if it is being
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
		/// <param name="opmode"> the operation mode of this cipher (this is one of the following: 
		/// <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
		/// <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate
		/// for this cipher, or if this cipher is being initialized for decryption and requires
		/// algorithm parameters and <code>params</code> is null. </exception>
		public abstract void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random);

		/// <summary>
		/// Initializes this cipher with a key, a set of
		/// algorithm parameters, and a source of randomness.
		/// <para>
		/// The cipher is initialized for one of the following four operations:
		/// encryption, decryption, key wrapping or key unwrapping, depending on
		/// the value of <code>opmode</code>.
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
		/// equivalent to creating a new instance of that Cipher and initializing it.
		/// 
		/// </para>
		/// </summary>
		/// <param name="opmode"> the operation mode of this cipher (this is one of the following: 
		/// <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code>
		/// or <code>UNWRAP_MODE</code>) </param>
		/// <param name="key"> the encryption key </param>
		/// <param name="params"> the algorithm parameters </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this cipher </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given algorithm parameters are inappropriate
		/// for this cipher, or if this cipher is being initialized for decryption and requires
		/// algorithm parameters and <code>params</code> is null. </exception>
		public abstract void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random);

		/// <summary>
		/// Continues a multiple-part encryption or decryption operation
		/// (depending on how this cipher was initialized), processing another data
		/// part.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, are processed,
		/// and the result is stored in a new buffer.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <returns> the new buffer with the result, or null if the underlying cipher is a
		/// block cipher and the input data is too short to result in a new block. </returns>
		public abstract byte[] engineUpdate(byte[] input, int inputOffset, int inputLen);

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
		/// a <code>ShortBufferException</code> is thrown.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <param name="outputOffset"> the offset in <code>output</code> where the result is stored </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small to hold the result </exception>
		public abstract int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
		/// The data is encrypted or decrypted, depending on how this cipher was initialized.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, and any input
		/// bytes that may have been buffered during a previous <code>update</code>
		/// operation, are processed, with padding (if requested) being applied.
		/// The result is stored in a new buffer.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to <code>engineInit</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>engineInit</code>) more data.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <returns> the new buffer with the result </returns>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher, no padding has been requested
		/// (only in encryption mode), and the total input length of the data processed by this cipher is not a
		/// multiple of block size </exception>
		/// <exception cref="BadPaddingException">  if this cipher is in decryption mode, and (un)padding has been requested,
		/// but the decrypted data is not bounded by the appropriate padding bytes </exception>
		public abstract byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen);

		/// <summary>
		/// Encrypts or decrypts data in a single-part operation,
		/// or finishes a multiple-part operation.
		/// The data is encrypted or decrypted, depending on how this cipher was
		/// initialized.
		/// <para>
		/// The first <code>inputLen</code> bytes in the <code>input</code>
		/// buffer, starting at <code>inputOffset</code> inclusive, and any input
		/// bytes that may have been buffered during a previous <code>update</code>
		/// operation, are processed, with padding (if requested) being applied.
		/// The result is stored in the <code>output</code> buffer, starting at
		/// <code>outputOffset</code> inclusive.
		/// </para>
		/// <para>
		/// If the <code>output</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown.
		/// </para>
		/// <para>
		/// A call to this method resets this cipher object to the state 
		/// it was in when previously initialized via a call to
		/// <code>engineInit</code>.
		/// That is, the object is reset and available to encrypt or decrypt
		/// (depending on the operation mode that was specified in the call to
		/// <code>engineInit</code>) more data.
		/// 
		/// </para>
		/// </summary>
		/// <param name="input"> the input buffer </param>
		/// <param name="inputOffset"> the offset in <code>input</code> where the input starts </param>
		/// <param name="inputLen"> the input length </param>
		/// <param name="output"> the buffer for the result </param>
		/// <param name="outputOffset"> the offset in <code>output</code> where the result is stored </param>
		/// <returns> the number of bytes stored in <code>output</code> </returns>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher, no padding has been
		/// requested (only in encryption mode), and the total input length of the data processed by this
		/// cipher is not a multiple of block size </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small to hold the result </exception>
		/// <exception cref="BadPaddingException"> if this cipher is in decryption mode, and (un)padding has been requested,
		/// but the decrypted data is not bounded by the appropriate padding bytes </exception>
		public abstract int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

		/// <summary>
		/// Wrap a key.
		/// <para>
		/// This concrete method has been added to this previously-defined
		/// abstract class. (For backwards compatibility, it cannot be abstract.)
		/// It may be overridden by a provider to wrap a key.
		/// Such an override is expected to throw an IllegalBlockSizeException or
		/// InvalidKeyException (under the specified circumstances),
		/// if the given key cannot be wrapped.
		/// If this method is not overridden, it always throws an
		/// UnsupportedOperationException.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the key to be wrapped. </param>
		/// <returns> the wrapped key. </returns>
		/// <exception cref="IllegalBlockSizeException"> if this cipher is a block cipher, no padding has been requested,
		/// and the length of the encoding of the key to be wrapped is not a multiple of the block size. </exception>
		/// <exception cref="InvalidKeyException"> if it is impossible or unsafe to wrap the key with this cipher (e.g.,
		/// a hardware protected key is being passed to a software-only cipher). </exception>
		public virtual byte[] engineWrap(Key key)
		{
			throw new UnsupportedOperationException("Underlying cipher does not support key wrapping");
		}

		/// <summary>
		/// Unwrap a previously wrapped key.
		/// 
		/// <para>This concrete method has been added to this previously-defined
		/// abstract class. (For backwards compatibility, it cannot be abstract.)
		/// It may be overridden by a provider to unwrap a previously wrapped key.
		/// Such an override is expected to throw an InvalidKeyException if
		/// the given wrapped key cannot be unwrapped.
		/// If this method is not overridden, it always throws an
		/// UnsupportedOperationException.
		/// 
		/// </para>
		/// </summary>
		/// <param name="wrappedKey"> the key to be unwrapped. </param>
		/// <param name="wrappedKeyAlgorithm"> the algorithm associated with the wrapped key. </param>
		/// <param name="wrappedKeyType"> the type of the wrapped key. This is one of <code>SECRET_KEY</code>,
		/// <code>PRIVATE_KEY</code>, or <code>PUBLIC_KEY</code>. </param>
		/// <returns> the unwrapped key. </returns>
		/// <exception cref="InvalidKeyException"> if <code>wrappedKey</code> does not represent a wrapped key,
		/// or if the algorithm associated with the wrapped key is different from <code>wrappedKeyAlgorithm</code> 
		/// and/or its key type is different from <code>wrappedKeyType</code>. </exception>
		/// <exception cref="NoSuchAlgorithmException"> - if no installed providers can create keys for the
		/// <code>wrappedKeyAlgorithm</code>. </exception>
		public virtual Key engineUnwrap(byte[] wrappedKey, string wrappedKeyAlgorithm, int wrappedKeyType)
		{
			throw new UnsupportedOperationException("Underlying cipher does not support key unwrapping");
		}

		/// <summary>
		/// Returns the key size of the given key object.
		/// <para>
		/// This concrete method has been added to this previously-defined
		/// abstract class. It throws an <code>UnsupportedOperationException</code>
		/// if it is not overridden by the provider.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the key object. </param>
		/// <returns> the key size of the given key object. </returns>
		/// <exception cref="InvalidKeyException"> if <code>key</code> is invalid. </exception>
		public virtual int engineGetKeySize(Key key)
		{
			throw new UnsupportedOperationException("Key size unavailable");
		}
	}

}