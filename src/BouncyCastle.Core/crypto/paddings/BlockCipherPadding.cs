using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.paddings
{

	/// <summary>
	/// Block cipher padders are expected to conform to this interface
	/// </summary>
	public interface BlockCipherPadding
	{
		/// <summary>
		/// Initialise the padder.
		/// </summary>
		/// <param name="random"> the source of randomness for the padding, if required. </param>
		void init(SecureRandom random);

		/// <summary>
		/// Return the name of the algorithm the cipher implements.
		/// </summary>
		/// <returns> the name of the algorithm the cipher implements. </returns>
		string getPaddingName();

		/// <summary>
		/// add the pad bytes to the passed in block, returning the
		/// number of bytes added.
		/// <para>
		/// Note: this assumes that the last block of plain text is always 
		/// passed to it inside in. i.e. if inOff is zero, indicating the
		/// entire block is to be overwritten with padding the value of in
		/// should be the same as the last block of plain text. The reason
		/// for this is that some modes such as "trailing bit compliment"
		/// base the padding on the last byte of plain text.
		/// </para>
		/// </summary>
		int addPadding(byte[] @in, int inOff);

		/// <summary>
		/// return the number of pad bytes present in the block. </summary>
		/// <exception cref="InvalidCipherTextException"> if the padding is badly formed
		/// or invalid. </exception>
		int padCount(byte[] @in);
	}

}