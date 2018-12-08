namespace org.bouncycastle.mime
{

	public interface MimeMultipartContext : MimeContext
	{
		MimeContext createContext(int partNo);
	}

}