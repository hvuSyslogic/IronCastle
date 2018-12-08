using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// The base interface for implementations of message authentication codes (MACs).
	/// </summary>
	public interface Mac
	{
		/// <summary>
		/// Initialise the MAC.
		/// </summary>
		/// <param name="params"> the key and other data required by the MAC. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		void init(CipherParameters @params);

		/// <summary>
		/// Return the name of the algorithm the MAC implements.
		/// </summary>
		/// <returns> the name of the algorithm the MAC implements. </returns>
		string getAlgorithmName();

		/// <summary>
		/// Return the block size for this MAC (in bytes).
		/// </summary>
		/// <returns> the block size for this MAC in bytes. </returns>
		int getMacSize();

		/// <summary>
		/// add a single byte to the mac for processing.
		/// </summary>
		/// <param name="in"> the byte to be processed. </param>
		/// <exception cref="IllegalStateException"> if the MAC is not initialised. </exception>
		void update(byte @in);

		/// <param name="in"> the array containing the input. </param>
		/// <param name="inOff"> the index in the array the data begins at. </param>
		/// <param name="len"> the length of the input starting at inOff. </param>
		/// <exception cref="IllegalStateException"> if the MAC is not initialised. </exception>
		/// <exception cref="DataLengthException"> if there isn't enough data in in. </exception>
		void update(byte[] @in, int inOff, int len);

		/// <summary>
		/// Compute the final stage of the MAC writing the output to the out
		/// parameter.
		/// <para>
		/// doFinal leaves the MAC in the same state it was after the last init.
		/// 
		/// </para>
		/// </summary>
		/// <param name="out"> the array the MAC is to be output to. </param>
		/// <param name="outOff"> the offset into the out buffer the output is to start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough space in out. </exception>
		/// <exception cref="IllegalStateException"> if the MAC is not initialised. </exception>
		int doFinal(byte[] @out, int outOff);

		/// <summary>
		/// Reset the MAC. At the end of resetting the MAC should be in the
		/// in the same state it was after the last init (if there was one).
		/// </summary>
		void reset();
	}

}