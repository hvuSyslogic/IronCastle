namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// A generic compressed data object.
	/// </summary>
	public class CompressedDataPacket : InputStreamPacket
	{
		internal int algorithm;

		public CompressedDataPacket(BCPGInputStream @in) : base(@in)
		{

			algorithm = @in.read();
		}

		/// <summary>
		/// Gets the <seealso cref="CompressionAlgorithmTags compression algorithm"/> used for this packet.
		/// </summary>
		/// <returns> the compression algorithm tag value. </returns>
		public virtual int getAlgorithm()
		{
			return algorithm;
		}
	}

}