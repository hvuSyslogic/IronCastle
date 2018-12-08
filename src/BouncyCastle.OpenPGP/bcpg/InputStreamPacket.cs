namespace org.bouncycastle.bcpg
{
	/// <summary>
	/// A block of data associated with other packets in a PGP object stream.
	/// </summary>
	public class InputStreamPacket : Packet
	{
		private BCPGInputStream @in;

		public InputStreamPacket(BCPGInputStream @in)
		{
			this.@in = @in;
		}

		/// <summary>
		/// Obtains an input stream to read the contents of the packet.
		/// <para>
		/// Note: you can only read from this once...
		/// </para> </summary>
		/// <returns> the data in this packet. </returns>
		public virtual BCPGInputStream getInputStream()
		{
			return @in;
		}
	}

}