using System;

namespace org.bouncycastle.mime
{

	using Iterable = org.bouncycastle.util.Iterable;
	using Strings = org.bouncycastle.util.Strings;

	public class Headers : Iterable<string>
	{
		private readonly Map<string, List> headers = new TreeMap<string, List>(string.CASE_INSENSITIVE_ORDER);
		private readonly List<string> headersAsPresented;
		private readonly string contentTransferEncoding;

		private string boundary;
		private bool multipart;
		private string contentType;
		private Map<string, string> contentTypeParameters;

		private static List<string> parseHeaders(InputStream src)
		{
			string s;
			List<string> headerLines = new ArrayList<string>();
			LineReader rd = new LineReader(src);

			while (!string.ReferenceEquals((s = rd.readLine()), null))
			{
				if (s.Length == 0)
				{
					break;
				}
				headerLines.add(s);
			}

			return headerLines;
		}

		public Headers(InputStream source, string defaultContentTransferEncoding) : this(parseHeaders(source), defaultContentTransferEncoding)
		{
		}

		public Headers(List<string> headerLines, string defaultContentTransferEncoding)
		{
			this.headersAsPresented = headerLines;

			string header = "";
			for (Iterator it = headerLines.iterator(); it.hasNext();)
			{
				string line = (string)it.next();
				if (line.StartsWith(" ", StringComparison.Ordinal) || line.StartsWith("\t", StringComparison.Ordinal))
				{
					header = header + line.Trim();
				}
				else
				{
					if (header.Length != 0)
					{
						this.put(header.Substring(0, header.IndexOf(':')).Trim(), header.Substring(header.IndexOf(':') + 1).Trim());
					}
					header = line;
				}
			}

			// pick up last header line
			if (header.Trim().Length != 0)
			{
				this.put(header.Substring(0, header.IndexOf(':')).Trim(), header.Substring(header.IndexOf(':') + 1).Trim());
			}

			string contentTypeHeader = (this.getValues("Content-Type") == null) ? "text/plain" : this.getValues("Content-Type")[0];

			int parameterIndex = contentTypeHeader.IndexOf(';');
			if (parameterIndex < 0)
			{
				contentType = contentTypeHeader;
				contentTypeParameters = Collections.EMPTY_MAP;
			}
			else
			{
				contentType = contentTypeHeader.Substring(0, parameterIndex);
				contentTypeParameters = createContentTypeParameters(contentTypeHeader.Substring(parameterIndex + 1).Trim());
			}

			contentTransferEncoding = this.getValues("Content-Transfer-Encoding") == null ? defaultContentTransferEncoding : this.getValues("Content-Transfer-Encoding")[0];

			if (contentType.IndexOf("multipart", StringComparison.Ordinal) >= 0)
			{
				multipart = true;
				string bound = (string)contentTypeParameters.get("boundary");
				boundary = bound.Substring(1, (bound.Length - 1) - 1); // quoted-string
			}
			else
			{
				boundary = null;
				multipart = false;
			}
		}

		/// <summary>
		/// Return the a Map of the ContentType attributes and their values.
		/// </summary>
		/// <returns> a Map of ContentType parameters - empty if none present. </returns>
		public virtual Map<string, string> getContentTypeAttributes()
		{
			return contentTypeParameters;
		}

		/// <summary>
		/// Return the a list of the ContentType parameters.
		/// </summary>
		/// <returns> a list of ContentType parameters - empty if none present. </returns>
		private Map<string, string> createContentTypeParameters(string contentTypeParameters)
		{
			string[] parameterSplit = contentTypeParameters.Split(";", true);
			Map<string, string> rv = new LinkedHashMap<string, string>();

			for (int i = 0; i != parameterSplit.Length; i++)
			{
				string parameter = parameterSplit[i];

				int eqIndex = parameter.IndexOf('=');
				if (eqIndex < 0)
				{
					throw new IllegalArgumentException("malformed Content-Type header");
				}

				rv.put(parameter.Substring(0, eqIndex).Trim(), parameter.Substring(eqIndex + 1).Trim());
			}

			return Collections.unmodifiableMap(rv);
		}

		public virtual bool isMultipart()
		{
			return multipart;
		}

		public virtual string getBoundary()
		{
			return boundary;
		}

		public virtual string getContentType()
		{
			return contentType;
		}

		public virtual string getContentTransferEncoding()
		{
			return contentTransferEncoding;
		}

		private void put(string field, string value)
		{
			lock (this)
			{
				KV kv = new KV(this, field, value);
				List<KV> list = (List<KV>)headers.get(field);
				if (list == null)
				{
					list = new ArrayList<KV>();
					headers.put(field, list);
				}
				list.add(kv);
			}
		}

		public virtual Iterator<string> getNames()
		{
			return headers.keySet().iterator();
		}

		public virtual string[] getValues(string header)
		{

			lock (this)
			{
				List<KV> kvList = (List<KV>)headers.get(header);
				if (kvList == null)
				{
					return null;
				}
				string[] @out = new string[kvList.size()];

				for (int t = 0; t < kvList.size(); t++)
				{
					@out[t] = ((KV)kvList.get(t)).value;
				}

				return @out;
			}
		}

		public virtual bool isEmpty()
		{
			lock (this)
			{
				return headers.isEmpty();
			}
		}

		public virtual bool containsKey(string s)
		{
			return headers.containsKey(s);
		}

		public virtual Iterator<string> iterator()
		{
			return headers.keySet().iterator();
		}

		public virtual void dumpHeaders(OutputStream outputStream)
		{
			for (Iterator it = headersAsPresented.iterator(); it.hasNext();)
			{
				outputStream.write(Strings.toUTF8ByteArray(it.next().ToString()));
				outputStream.write('\r');
				outputStream.write('\n');
			}
		}

		public class KV
		{
			private readonly Headers outerInstance;

			public readonly string key;
			public readonly string value;

			public KV(Headers outerInstance, string key, string value)
			{
				this.outerInstance = outerInstance;
				this.key = key;
				this.value = value;
			}

			public KV(Headers outerInstance, KV kv)
			{
				this.outerInstance = outerInstance;
				this.key = kv.key;
				this.value = kv.value;
			}
		}
	}

}