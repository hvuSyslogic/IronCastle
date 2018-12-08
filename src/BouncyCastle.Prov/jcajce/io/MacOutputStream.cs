namespace org.bouncycastle.jcajce.io
{

	/// <summary>
	/// An output stream which calculates a MAC based on the data that is written to it.
	/// </summary>
	public sealed class MacOutputStream : OutputStream
	{
		private Mac mac;

		/// <summary>
		/// Base constructor - specify the MAC algorithm to use.
		/// </summary>
		/// <param name="mac"> the MAC implementation to use as the basis of the stream. </param>
		public MacOutputStream(Mac mac)
		{
			this.mac = mac;
		}

		/// <summary>
		/// Write a single byte to the stream.
		/// </summary>
		/// <param name="b"> the byte value to write. </param>
		/// <exception cref="IOException">  in case of failure. </exception>
		public void write(int b)
		{
			mac.update((byte)b);
		}

		/// <summary>
		/// Write a block of data of length len starting at offset off in the byte array bytes to
		/// the stream.
		/// </summary>
		/// <param name="bytes"> byte array holding the data. </param>
		/// <param name="off"> offset into bytes that the data starts at. </param>
		/// <param name="len"> the length of the data block to write. </param>
		/// <exception cref="IOException"> in case of failure. </exception>
		public void write(byte[] bytes, int off, int len)
		{
			mac.update(bytes, off, len);
		}

		/// <summary>
		/// Execute doFinal() and return the calculated MAC.
		/// </summary>
		/// <returns> the MAC calculated from the output written to the stream. </returns>
		public byte[] getMac()
		{
			return mac.doFinal();
		}
	}

}