namespace org.bouncycastle.crypto
{

	/// <summary>
	/// base interface that a public/private key block cipher needs
	/// to conform to.
	/// </summary>
	public interface AsymmetricBlockCipher
	{
		/// <summary>
		/// initialise the cipher.
		/// </summary>
		/// <param name="forEncryption"> if true the cipher is initialised for 
		///  encryption, if false for decryption. </param>
		/// <param name="param"> the key and other data required by the cipher. </param>
		void init(bool forEncryption, CipherParameters param);

		/// <summary>
		/// returns the largest size an input block can be.
		/// </summary>
		/// <returns> maximum size for an input block. </returns>
		int getInputBlockSize();

		/// <summary>
		/// returns the maximum size of the block produced by this cipher.
		/// </summary>
		/// <returns> maximum size of the output block produced by the cipher. </returns>
		int getOutputBlockSize();

		/// <summary>
		/// process the block of len bytes stored in in from offset inOff.
		/// </summary>
		/// <param name="in"> the input data </param>
		/// <param name="inOff"> offset into the in array where the data starts </param>
		/// <param name="len"> the length of the block to be processed. </param>
		/// <returns> the resulting byte array of the encryption/decryption process. </returns>
		/// <exception cref="InvalidCipherTextException"> data decrypts improperly. </exception>
		/// <exception cref="DataLengthException"> the input data is too large for the cipher. </exception>
		byte[] processBlock(byte[] @in, int inOff, int len);
	}

}