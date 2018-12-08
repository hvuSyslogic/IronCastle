namespace org.bouncycastle.est
{

	/// <summary>
	/// ESTSourceConnectionListener is called when the source is
	/// is connected to the remote end point but no application
	/// data has been sent.
	/// </summary>
	public interface ESTSourceConnectionListener<T, I>
	{
		ESTRequest onConnection(Source<T> source, ESTRequest request);
	}

}