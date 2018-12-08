using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto
{
	/// <summary>
	/// Ciphers producing a key stream which can be reset to particular points in the stream implement this.
	/// </summary>
	public interface SkippingCipher
	{
		/// <summary>
		/// Skip numberOfBytes forwards, or backwards.
		/// </summary>
		/// <param name="numberOfBytes"> the number of bytes to skip (positive forward, negative backwards). </param>
		/// <returns> the number of bytes actually skipped. </returns>
		/// <exception cref="IllegalArgumentException"> if numberOfBytes is an invalid value. </exception>
		long skip(long numberOfBytes);

		/// <summary>
		/// Reset the cipher and then skip forward to a given position.
		/// </summary>
		/// <param name="position"> the number of bytes in to set the cipher state to. </param>
		/// <returns> the byte position moved to. </returns>
		long seekTo(long position);

		/// <summary>
		/// Return the current "position" of the cipher
		/// </summary>
		/// <returns> the current byte position. </returns>
		long getPosition();
	}

}