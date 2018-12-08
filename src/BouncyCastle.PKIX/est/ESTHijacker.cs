namespace org.bouncycastle.est
{

	/// <summary>
	/// ESTHijacker can take control of the source after the initial http request
	/// has been sent and a response received.
	/// A hijacker is then able to send more request or be able to modify the response before returning a response
	/// to the original caller.
	/// <para>
	/// See DigestAuth and BasicAuth.
	/// </para>
	/// </summary>
	public interface ESTHijacker
	{
		ESTResponse hijack(ESTRequest req, Source sock);
	}

}