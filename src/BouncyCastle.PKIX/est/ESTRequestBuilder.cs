namespace org.bouncycastle.est
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Builder for basic EST requests
	/// </summary>
	public class ESTRequestBuilder
	{
		private readonly string method;
		private URL url;

		private HttpUtil.Headers headers;
		internal ESTHijacker hijacker;
		internal ESTSourceConnectionListener listener;
		internal ESTClient client;
		private byte[] data;

		public ESTRequestBuilder(ESTRequest request)
		{

			this.method = request.method;
			this.url = request.url;
			this.listener = request.listener;
			this.data = request.data;
			this.hijacker = request.hijacker;
			this.headers = (HttpUtil.Headers)request.headers.clone();
			this.client = request.getClient();
		}

		public ESTRequestBuilder(string method, URL url)
		{
			this.method = method;
			this.url = url;
			this.headers = new HttpUtil.Headers();
		}

		public virtual ESTRequestBuilder withConnectionListener(ESTSourceConnectionListener listener)
		{
			this.listener = listener;

			return this;
		}

		public virtual ESTRequestBuilder withHijacker(ESTHijacker hijacker)
		{
			this.hijacker = hijacker;

			return this;
		}

		public virtual ESTRequestBuilder withURL(URL url)
		{
			this.url = url;

			return this;
		}

		public virtual ESTRequestBuilder withData(byte[] data)
		{
			this.data = Arrays.clone(data);

			return this;
		}

		public virtual ESTRequestBuilder addHeader(string key, string value)
		{
			headers.add(key, value);
			return this;
		}

		public virtual ESTRequestBuilder setHeader(string key, string value)
		{
			headers.set(key, value);
			return this;
		}

		public virtual ESTRequestBuilder withClient(ESTClient client)
		{
			this.client = client;
			return this;
		}

		public virtual ESTRequest build()
		{
			return new ESTRequest(method, url, data, hijacker, listener, headers, client);
		}
	}

}