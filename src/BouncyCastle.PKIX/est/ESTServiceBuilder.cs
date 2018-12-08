namespace org.bouncycastle.est
{

	/// <summary>
	/// Build an RFC7030 (EST) service.
	/// </summary>
	public class ESTServiceBuilder
	{
		protected internal readonly string server;
		protected internal ESTClientProvider clientProvider;
		protected internal string label;

		/// <summary>
		/// With scheme and host..
		/// </summary>
		/// <param name="server"> The authority name, eg estserver.co.au </param>
		public ESTServiceBuilder(string server)
		{
			this.server = server;
		}

		/// <summary>
		/// Set the label as per https://tools.ietf.org/html/rfc7030#section-3.2.2
		/// </summary>
		/// <param name="label"> The label. </param>
		/// <returns> this builder. </returns>
		public virtual ESTServiceBuilder withLabel(string label)
		{
			this.label = label;
			return this;
		}

		/// <summary>
		/// Set the client provider.
		/// </summary>
		/// <param name="clientProvider"> The client provider.
		/// @return </param>
		public virtual ESTServiceBuilder withClientProvider(ESTClientProvider clientProvider)
		{
			this.clientProvider = clientProvider;
			return this;
		}

		/// <summary>
		/// Build the service.
		/// </summary>
		/// <returns> an ESTService. </returns>
		public virtual ESTService build()
		{
			return new ESTService(server, label, clientProvider);
		}

	}




}