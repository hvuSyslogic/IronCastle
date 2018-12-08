namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// Base interface for an object sending and receiving DTLS data.
	/// </summary>
	public interface DatagramTransport
	{
		int getReceiveLimit();

		int getSendLimit();

		int receive(byte[] buf, int off, int len, int waitMillis);

		void send(byte[] buf, int off, int len);

		void close();
	}

}