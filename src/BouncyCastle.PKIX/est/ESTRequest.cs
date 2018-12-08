namespace org.bouncycastle.est
{

	/// <summary>
	/// Implements a basic http request.
	/// </summary>
	public class ESTRequest
	{
		internal readonly string method;
		internal readonly URL url;
		internal HttpUtil.Headers headers = new HttpUtil.Headers();
		internal readonly byte[] data;
		internal readonly ESTHijacker hijacker;
		internal readonly ESTClient estClient;
		internal readonly ESTSourceConnectionListener listener;

		public ESTRequest(string method, URL url, byte[] data, ESTHijacker hijacker, ESTSourceConnectionListener listener, HttpUtil.Headers headers, ESTClient estClient)
		{
			this.method = method;
			this.url = url;
			this.data = data;
			this.hijacker = hijacker;
			this.listener = listener;
			this.headers = headers;
			this.estClient = estClient;
		}

		public virtual string getMethod()
		{
			return method;
		}

		public virtual URL getURL()
		{
			return url;
		}

		public virtual Map<string, String[]> getHeaders()
		{
			return (Map<string, String[]>)headers.clone();
		}

		public virtual ESTHijacker getHijacker()
		{
			return hijacker;
		}

		public virtual ESTClient getClient()
		{
			return estClient;
		}

		public virtual ESTSourceConnectionListener getListener()
		{
			return listener;
		}

		public virtual void writeData(OutputStream os)
		{
			if (data != null)
			{
				os.write(data);
			}
		}
	}

}