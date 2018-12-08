namespace org.bouncycastle.openpgp
{

	/// <summary>
	/// Callback interface for generators that produce a stream to be informed when the stream has been
	/// closed by the client.
	/// </summary>
	public interface StreamGenerator
	{
		/// <summary>
		/// Signal that the stream has been closed.
		/// </summary>
		void close();
	}

}