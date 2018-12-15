using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util
{

	public interface StreamParser
	{
		object read();

		Collection readAll();
	}

}