namespace javax.crypto
{

	/// <summary>
	/// This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
	/// for the <code>KeyAgreement</code> class.
	/// All the abstract methods in this class must be implemented by each 
	/// cryptographic service provider who wishes to supply the implementation
	/// of a particular key agreement algorithm.
	/// <para>
	/// The keys involved in establishing a shared secret are created by one of the
	/// key generators (<code>KeyPairGenerator</code> or <code>KeyGenerator</code>),
	/// a <code>KeyFactory</code>, or as a result from an intermediate phase of the key
	/// agreement protocol (see <a href = "#engineDoPhase(java.security.Key, boolean)">engineDoPhase</a>).
	/// </para>
	/// <para>
	/// For each of the correspondents in the key exchange, <code>engineDoPhase</code>
	/// needs to be called. For example, if the key exchange is with one other
	/// party, <code>engineDoPhase</code> needs to be called once, with the
	/// <code>lastPhase</code> flag set to <code>true</code>.
	/// If the key exchange is with two other parties, <code>engineDoPhase</code> needs to be called twice,
	/// the first time setting the <code>lastPhase</code> flag to
	/// <code>false</code>, and the second time setting it to <code>true</code>.
	/// There may be any number of parties involved in a key exchange.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= KeyGenerator </seealso>
	/// <seealso cref= SecretKey </seealso>
	public abstract class KeyAgreementSpi
	{
		public KeyAgreementSpi()
		{
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
		/// of the Diffie-Hellman key agreement, this would be the party's own Diffie-Hellman private key. </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for this key agreement, e.g., is
		///  of the wrong type or has an incompatible algorithm type. </exception>
		public abstract void engineInit(Key key, SecureRandom random);

		/// <summary>
		/// Initializes this key agreement with the given key, set of
		/// algorithm parameters, and source of randomness.
		/// </summary>
		/// <param name="key"> the party's private information. For example, in the case
		/// of the Diffie-Hellman key agreement, this would be the party's own
		/// Diffie-Hellman private key. </param>
		/// <param name="params"> the key agreement parameters </param>
		/// <param name="random"> the source of randomness </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for this key agreement, e.g., is of the
		/// wrong type or has an incompatible algorithm type. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> if the given parameters are inappropriate for this key
		/// agreement. </exception>
		public abstract void engineInit(Key key, AlgorithmParameterSpec @params, SecureRandom random);

		/// <summary>
		/// Executes the next phase of this key agreement with the given
		/// key that was received from one of the other parties involved in this key
		/// agreement. </summary>
		/// <param name="key">  the key for this phase. For example, in the case of
		/// Diffie-Hellman between 2 parties, this would be the other party's
		/// Diffie-Hellman public key. </param>
		/// <param name="lastPhase"> flag which indicates whether or not this is the last
		/// phase of this key agreement. </param>
		/// <returns> the (intermediate) key resulting from this phase, or null if this phase does not yield a key </returns>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for this phase. </exception>
		/// <exception cref="IllegalStateException"> if this key agreement has not been initialized. </exception>
		public abstract Key engineDoPhase(Key key, bool lastPhase);

		/// <summary>
		/// Generates the shared secret and returns it in a new buffer.
		/// <para>
		/// This method resets this <code>KeyAgreementSpi</code> object, so that it
		/// can be reused for further key agreements. Unless this key agreement is
		/// reinitialized with one of the <code>engineInit</code> methods, the same
		/// private information and algorithm parameters will be used for
		/// subsequent key agreements.
		/// </para>
		/// </summary>
		/// <returns> the new buffer with the shared secret </returns>
		/// <exception cref="IllegalStateException"> if this key agreement has not been completed yet </exception>
		public abstract byte[] engineGenerateSecret();

		/// <summary>
		/// Generates the shared secret, and places it into the buffer
		/// <code>sharedSecret</code>, beginning at <code>offset</code> inclusive.
		/// <para>
		/// If the <code>sharedSecret</code> buffer is too small to hold the result,
		/// a <code>ShortBufferException</code> is thrown. In this case, this call should be
		/// repeated with a larger output buffer. 
		/// </para>
		/// <para>
		/// This method resets this <code>KeyAgreementSpi</code> object, so that it
		/// can be reused for further key agreements. Unless this key agreement is
		/// reinitialized with one of the <code>engineInit</code> methods, the same
		/// private information and algorithm parameters will be used for subsequent key agreements.
		/// 
		/// </para>
		/// </summary>
		/// <param name="sharedSecret"> the buffer for the shared secret </param>
		/// <param name="offset"> the offset in <code>sharedSecret</code> where the shared secret will be stored </param>
		/// <returns> the number of bytes placed into <code>sharedSecret</code> </returns>
		/// <exception cref="IllegalStateException"> if this key agreement has not been completed yet </exception>
		/// <exception cref="ShortBufferException"> if the given output buffer is too small to hold the secret </exception>
		public abstract int engineGenerateSecret(byte[] sharedSecret, int offset);

		/// <summary>
		/// Creates the shared secret and returns it as a secret key object
		/// of the requested algorithm type.
		/// <para>
		/// This method resets this <code>KeyAgreementSpi</code> object, so that it
		/// can be reused for further key agreements. Unless this key agreement is
		/// reinitialized with one of the <code>engineInit</code> methods, the same
		/// private information and algorithm parameters will be used for
		/// subsequent key agreements.
		/// 
		/// </para>
		/// </summary>
		/// <param name="algorithm"> the requested secret key algorithm </param>
		/// <returns> the shared secret key </returns>
		/// <exception cref="IllegalStateException"> if this key agreement has not been completed yet </exception>
		/// <exception cref="NoSuchAlgorithmException"> if the requested secret key algorithm is not available </exception>
		/// <exception cref="InvalidKeyException"> if the shared secret key material cannot be used to generate
		/// a secret key of the requested algorithm type (e.g., the key material is too short) </exception>
		public abstract SecretKey engineGenerateSecret(string algorithm);
	}

}