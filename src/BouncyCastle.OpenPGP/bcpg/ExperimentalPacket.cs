namespace org.bouncycastle.bcpg
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// basic packet for an experimental packet.
	/// </summary>
	public class ExperimentalPacket : ContainedPacket, PublicKeyAlgorithmTags
	{
		private int tag;
		private byte[] contents;

		/// 
		/// <param name="in"> </param>
		/// <exception cref="IOException"> </exception>
		public ExperimentalPacket(int tag, BCPGInputStream @in)
		{
			this.tag = tag;
			this.contents = @in.readAll();
		}

		public virtual int getTag()
		{
			return tag;
		}

		public virtual byte[] getContents()
		{
			return Arrays.clone(contents);
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(tag, contents, true);
		}
	}

}