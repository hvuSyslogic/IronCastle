namespace org.bouncycastle.est.jcajce
{

	/// <summary>
	/// Verify the host name is as expected after the SSL Handshake has been completed.
	/// </summary>
	public interface JsseHostnameAuthorizer
	{
		/// <summary>
		/// Verify the passed in host name according to the context object.
		/// </summary>
		/// <param name="name">    name of the host to be verified. </param>
		/// <param name="context"> context object to do the verification under. </param>
		/// <returns> true if name verified, false otherwise. </returns>
		bool verified(string name, SSLSession context);
	}

}