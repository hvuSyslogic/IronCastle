namespace org.bouncycastle.est
{
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using Store = org.bouncycastle.util.Store;


	/// <summary>
	/// Holder class for a response containing the details making up a /simpleenroll response.
	/// </summary>
	public class EnrollmentResponse
	{
		private readonly Store<X509CertificateHolder> store;
		private readonly long notBefore;
		private readonly ESTRequest requestToRetry;
		private readonly Source source;

		public EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTRequest requestToRetry, Source session)
		{
			this.store = store;
			this.notBefore = notBefore;
			this.requestToRetry = requestToRetry;
			this.source = session;
		}

		public virtual bool canRetry()
		{
			return notBefore < System.currentTimeMillis();
		}

		public virtual Store<X509CertificateHolder> getStore()
		{
			return store;
		}

		public virtual long getNotBefore()
		{
			return notBefore;
		}

		public virtual ESTRequest getRequestToRetry()
		{
			return requestToRetry;
		}

		public virtual object getSession()
		{
			return source.getSession();
		}

		public virtual Source getSource()
		{
			return source;
		}

		public virtual bool isCompleted()
		{
			return requestToRetry == null;
		}
	}

}