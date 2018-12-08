namespace org.bouncycastle.est
{

	/// <summary>
	/// ESTClient implement connection to the server.
	/// <para>
	/// Implementations should be aware that they are responsible for
	/// satisfying <a href="https://tools.ietf.org/html/rfc7030#section-3.3">RFC7030 3.3 - TLS Layer</a>
	/// including SRP modes.
	/// </para>
	/// </summary>
	public interface ESTClient
	{
		ESTResponse doRequest(ESTRequest c);
	}

}