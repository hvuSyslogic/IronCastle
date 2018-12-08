namespace org.bouncycastle.cms
{

	using Streams = org.bouncycastle.util.io.Streams;

	public class CMSProcessableInputStream : CMSProcessable, CMSReadable
	{
		private InputStream input;
		private bool used = false;

		public CMSProcessableInputStream(InputStream input)
		{
			this.input = input;
		}

		public virtual InputStream getInputStream()
		{
			checkSingleUsage();

			return input;
		}

		public virtual void write(OutputStream zOut)
		{
			checkSingleUsage();

			Streams.pipeAll(input, zOut);
			input.close();
		}

		public virtual object getContent()
		{
			return getInputStream();
		}

		private void checkSingleUsage()
		{
			lock (this)
			{
				if (used)
				{
					throw new IllegalStateException("CMSProcessableInputStream can only be used once");
				}
        
				used = true;
			}
		}
	}

}