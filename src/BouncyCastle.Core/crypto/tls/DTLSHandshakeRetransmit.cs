namespace org.bouncycastle.crypto.tls
{

	public interface DTLSHandshakeRetransmit
	{
		void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len);
	}

}