namespace org.bouncycastle.mime
{

	public interface MimeParserProvider
	{
		MimeParser createParser(InputStream source);

		MimeParser createParser(Headers headers, InputStream source);
	}

}