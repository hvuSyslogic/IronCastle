namespace javax.crypto
{

	/// <summary>
	/// This class defines the <i>Service Provider Interface</i> (<b>SPI</b>)
	/// for the <code>Mac</code> class.
	/// All the abstract methods in this class must be implemented by each 
	/// cryptographic service provider who wishes to supply the implementation
	/// of a particular MAC algorithm.
	/// <para>
	/// Implementations are free to implement the Cloneable interface.
	/// </para>
	/// </summary>
	public abstract class MacSpi
	{
		public MacSpi()
		{
		}

		/// <summary>
		/// Returns the length of the MAC in bytes.
		/// </summary>
		/// <returns> the MAC length in bytes. </returns>
		public abstract int engineGetMacLength();

		/// <summary>
		/// Initializes the MAC with the given (secret) key and algorithm
		/// parameters.
		/// </summary>
		/// <param name="key"> - the (secret) key. </param>
		/// <param name="params"> - the algorithm parameters. </param>
		/// <exception cref="InvalidKeyException"> if the given key is inappropriate for initializing this MAC. </exception>
		/// <exception cref="InvalidAlgorithmParameterException"> - if the given algorithm parameters are inappropriate
		/// for this MAC. </exception>
		public abstract void engineInit(Key key, AlgorithmParameterSpec @params);

		/// <summary>
		/// Processes the given byte.
		/// </summary>
		/// <param name="input"> - the input byte to be processed. </param>
		public abstract void engineUpdate(byte input);

		/// <summary>
		/// Processes the first <code>len</code> bytes in <code>input</code>,
		/// starting at <code>offset</code> inclusive.
		/// </summary>
		/// <param name="input"> the input buffer. </param>
		/// <param name="offset"> the offset in <code>input</code> where the input starts. </param>
		/// <param name="len"> the number of bytes to process. </param>
		public abstract void engineUpdate(byte[] input, int offset, int len);

		/// <summary>
		/// Completes the MAC computation and resets the MAC for further use,
		/// maintaining the secret key that the MAC was initialized with.
		/// </summary>
		/// <returns> the MAC result. </returns>
		public abstract byte[] engineDoFinal();

		/// <summary>
		/// Resets the MAC for further use, maintaining the secret key that the
		/// MAC was initialized with.
		/// </summary>
		public abstract void engineReset();

		/// <summary>
		/// Returns a clone if the implementation is cloneable.
		/// </summary>
		/// <returns> a clone if the implementation is cloneable. </returns>
		/// <exception cref="CloneNotSupportedException"> if this is called on an implementation that does not support
		/// <code>Cloneable</code>. </exception>
		public virtual object clone()
		{
			throw new CloneNotSupportedException("Underlying MAC does not support cloning");
		}
	}

}