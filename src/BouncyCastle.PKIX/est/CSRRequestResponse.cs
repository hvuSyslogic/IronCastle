namespace org.bouncycastle.est
{
	/// <summary>
	/// Holder class for a response containing the details making up /csrattrs response.
	/// </summary>
	public class CSRRequestResponse
	{
		private readonly CSRAttributesResponse attributesResponse;
		private readonly Source source;

		public CSRRequestResponse(CSRAttributesResponse attributesResponse, Source session)
		{
			this.attributesResponse = attributesResponse;
			this.source = session;
		}

		public virtual bool hasAttributesResponse()
		{
			return attributesResponse != null;
		}

		public virtual CSRAttributesResponse getAttributesResponse()
		{
			if (attributesResponse == null)
			{
				throw new IllegalStateException("Response has no CSRAttributesResponse.");
			}
			return attributesResponse;
		}

		public virtual object getSession()
		{
			return source.getSession();
		}

		public virtual Source getSource()
		{
			return source;
		}
	}

}