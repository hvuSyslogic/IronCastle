namespace org.bouncycastle.mime
{

	public class ConstantMimeContext : MimeContext, MimeMultipartContext
	{
		public virtual InputStream applyContext(Headers headers, InputStream contentStream)
		{
			return contentStream;
		}

		public virtual MimeContext createContext(int partNo)
		{
			return this;
		}
	}

}