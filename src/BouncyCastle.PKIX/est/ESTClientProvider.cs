namespace org.bouncycastle.est
{

	/// <summary>
	/// A client provider is responsible for creating an ESTClient instance.
	/// </summary>
	public interface ESTClientProvider
	{
		ESTClient makeClient();

		/// <summary>
		/// Return true if the client is presently configured to verify the server.
		/// </summary>
		/// <returns> true = verifying server. </returns>
		bool isTrusted();
	}

}