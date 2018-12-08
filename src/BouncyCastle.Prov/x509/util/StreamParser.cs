namespace org.bouncycastle.x509.util
{

	public interface StreamParser
	{
		object read();

		Collection readAll();
	}

}