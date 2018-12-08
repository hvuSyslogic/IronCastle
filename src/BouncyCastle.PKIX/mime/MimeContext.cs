namespace org.bouncycastle.mime
{

	public interface MimeContext
	{
		InputStream applyContext(Headers headers, InputStream contentStream);
	}

}