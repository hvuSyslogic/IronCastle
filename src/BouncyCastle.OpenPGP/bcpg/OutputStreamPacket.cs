namespace org.bouncycastle.bcpg
{

	public abstract class OutputStreamPacket
	{
		protected internal BCPGOutputStream @out;

		public OutputStreamPacket(BCPGOutputStream @out)
		{
			this.@out = @out;
		}

		public abstract BCPGOutputStream open();

		public abstract void close();
	}

}