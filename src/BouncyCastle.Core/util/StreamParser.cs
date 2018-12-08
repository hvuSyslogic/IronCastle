namespace org.bouncycastle.util
{

	public interface StreamParser
	{
		object read();

		Collection readAll();
	}

}