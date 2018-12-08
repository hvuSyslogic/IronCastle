namespace org.bouncycastle.est
{

	/// <summary>
	/// ESTClientSourceProvider, implementations of this are expected to return a source.
	/// </summary>
	public interface ESTClientSourceProvider
	{
		Source makeSource(string host, int port);
	}

}