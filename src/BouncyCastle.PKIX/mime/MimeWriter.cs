namespace org.bouncycastle.mime
{

	public abstract class MimeWriter
	{
		protected internal readonly Headers headers;

		public MimeWriter(Headers headers)
		{
			this.headers = headers;
		}

		public virtual Headers getHeaders()
		{
			return headers;
		}

		public abstract OutputStream getContentStream();


		protected internal static List<string> mapToLines(Map<string, string> headers)
		{
			List hdrs = new ArrayList(headers.size());

			for (Iterator<string> it = headers.keySet().iterator(); it.hasNext();)
			{
				string key = (string)it.next();

				hdrs.add(key + ": " + headers.get(key));
			}

			return hdrs;
		}
	}

}