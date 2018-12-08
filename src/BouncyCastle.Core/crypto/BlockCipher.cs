using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// Block cipher engines are expected to conform to this interface.
	/// </summary>
	public interface BlockCipher
	{
		/// <summary>
		/// Initialise the cipher.
		/// </summary>
		/// <param name="forEncryption"> if true the cipher is initialised for
		///  encryption, if false for decryption. </param>
		/// <param name="params"> the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		void init(bool forEncryption, CipherParameters @params);

		/// <summary>
		/// Return the name of the algorithm the cipher implements.
		/// </summary>
		/// <returns> the name of the algorithm the cipher implements. </returns>
		string getAlgorithmName();

		/// <summary>
		/// Return the block size for this cipher (in bytes).
		/// </summary>
		/// <returns> the block size for this cipher in bytes. </returns>
		int getBlockSize();

		/// <summary>
		/// Process one block of input from the array in and write it to
		/// the out array.
		/// </summary>
		/// <param name="in"> the array containing the input data. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the output data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		int processBlock(byte[] @in, int inOff, byte[] @out, int outOff);

		/// <summary>
		/// Reset the cipher. After resetting the cipher is in the same state
		/// as it was after the last init (if there was one).
		/// </summary>
		void reset();
	}

}