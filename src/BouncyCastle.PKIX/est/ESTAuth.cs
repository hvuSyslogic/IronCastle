namespace org.bouncycastle.est
{

	/// <summary>
	/// Base interface for an object with adds HTTP Auth attributes to an ESTRequest
	/// </summary>
	public interface ESTAuth
	{
		/// <summary>
		/// Add the Auth attributes to the passed in request builder.
		/// </summary>
		/// <param name="reqBldr"> the builder for the request needing the Auth attributes. </param>
		void applyAuth(ESTRequestBuilder reqBldr);
	}

}