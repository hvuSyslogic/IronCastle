namespace org.bouncycastle.crypto
{
	/// <summary>
	/// With FIPS PUB 202 a new kind of message digest was announced which supported extendable output, or variable digest sizes.
	/// This interface provides the extra method required to support variable output on an extended digest implementation.
	/// </summary>
	public interface Xof : ExtendedDigest
	{
		/// <summary>
		/// Output the results of the final calculation for this digest to outLen number of bytes.
		/// </summary>
		/// <param name="out"> output array to write the output bytes to. </param>
		/// <param name="outOff"> offset to start writing the bytes at. </param>
		/// <param name="outLen"> the number of output bytes requested. </param>
		/// <returns> the number of bytes written </returns>
		int doFinal(byte[] @out, int outOff, int outLen);

		/// <summary>
		/// Start outputting the results of the final calculation for this digest. Unlike doFinal, this method
		/// will continue producing output until the Xof is explicitly reset, or signals otherwise.
		/// </summary>
		/// <param name="out"> output array to write the output bytes to. </param>
		/// <param name="outOff"> offset to start writing the bytes at. </param>
		/// <param name="outLen"> the number of output bytes requested. </param>
		/// <returns> the number of bytes written </returns>
		int doOutput(byte[] @out, int outOff, int outLen);
	}

}