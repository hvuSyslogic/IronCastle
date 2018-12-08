namespace org.bouncycastle.mime
{

	using Base64InputStream = org.bouncycastle.mime.encoding.Base64InputStream;
	using QuotedPrintableInputStream = org.bouncycastle.mime.encoding.QuotedPrintableInputStream;

	public class BasicMimeParser : MimeParser
	{
		private readonly InputStream src;
		private readonly MimeParserContext parserContext;
		private readonly string defaultContentTransferEncoding;
		private Headers headers;

//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private bool isMultipart_Renamed = false;
		private readonly string boundary;

		public BasicMimeParser(InputStream src) : this(null, new Headers(src, "7bit"), src)
		{
		}

		public BasicMimeParser(MimeParserContext parserContext, InputStream src) : this(parserContext, new Headers(src, parserContext.getDefaultContentTransferEncoding()), src)
		{
		}

		public BasicMimeParser(Headers headers, InputStream content) : this(null, headers, content)
		{
		}

		public BasicMimeParser(MimeParserContext parserContext, Headers headers, InputStream src)
		{
			if (headers.isMultipart())
			{
				isMultipart_Renamed = true;
				boundary = headers.getBoundary();
			}
			else
			{
				boundary = null;
			}

			this.headers = headers;
			this.parserContext = parserContext;
			this.src = src;
			this.defaultContentTransferEncoding = (parserContext != null) ? parserContext.getDefaultContentTransferEncoding() : "7bit";
		}



		public virtual void parse(MimeParserListener listener)
		{
			MimeContext context = listener.createContext(parserContext, headers);

			string s;
			if (isMultipart_Renamed) // Signed
			{
				MimeMultipartContext mContext = (MimeMultipartContext)context;
				string startBoundary = "--" + boundary;
				bool startFound = false;
				int partNo = 0;
				LineReader rd = new LineReader(src);
				while (!string.ReferenceEquals((s = rd.readLine()), null) && !"--".Equals(s))
				{
					if (startFound)
					{
						InputStream inputStream = new BoundaryLimitedInputStream(src, boundary);
						Headers headers = new Headers(inputStream, defaultContentTransferEncoding);

						MimeContext partContext = mContext.createContext(partNo++);
						inputStream = partContext.applyContext(headers, inputStream);

						listener.@object(parserContext, headers, processStream(headers, inputStream));

						if (inputStream.read() >= 0)
						{
							throw new IOException("MIME object not fully processed");
						}
					}
					else if (startBoundary.Equals(s))
					{
						startFound = true;
						InputStream inputStream = new BoundaryLimitedInputStream(src, boundary);
						Headers headers = new Headers(inputStream, defaultContentTransferEncoding);

						MimeContext partContext = mContext.createContext(partNo++);
						inputStream = partContext.applyContext(headers, inputStream);

						listener.@object(parserContext, headers, processStream(headers, inputStream));

						if (inputStream.read() >= 0)
						{
							throw new IOException("MIME object not fully processed");
						}
					}
				}
			}
			else
			{
				InputStream inputStream = context.applyContext(headers, src);

				listener.@object(parserContext, headers, processStream(headers, inputStream));
			}
		}

		public virtual bool isMultipart()
		{
			return isMultipart_Renamed;
		}

		private InputStream processStream(Headers headers, InputStream inputStream)
		{
			if (headers.getContentTransferEncoding().Equals("base64"))
			{
				return new Base64InputStream(inputStream);
			}
			else if (headers.getContentTransferEncoding().Equals("quoted-printable"))
			{
				return new QuotedPrintableInputStream(inputStream);
			}
			else
			{
				return inputStream;
			}
		}
	}

}