namespace org.bouncycastle.crypto.test.cavp
{

	public interface CAVPListener
	{
		void setup();

		void receiveStart(string name);

		void receiveCAVPVectors(string name, Properties config, Properties vectors);

		void receiveCommentLine(string commentLine);

		void receiveEnd();

		void tearDown();
	}

}