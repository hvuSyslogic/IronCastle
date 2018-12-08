using System;

namespace org.bouncycastle.est
{

	using Properties = org.bouncycastle.util.Properties;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A basic http response.
	/// </summary>
	public class ESTResponse
	{
		private readonly ESTRequest originalRequest;
		private readonly HttpUtil.Headers headers;
		private readonly byte[] lineBuffer;
		private readonly Source source;
		private string HttpVersion;
		private int statusCode;
		private string statusMessage;
		private InputStream inputStream;
		private long? contentLength;
		private long read = 0;
		private long? absoluteReadLimit;

		private const long? ZERO = 0L;

		public ESTResponse(ESTRequest originalRequest, Source source)
		{
			this.originalRequest = originalRequest;
			this.source = source;

			if (source is LimitedSource)
			{
				this.absoluteReadLimit = ((LimitedSource)source).getAbsoluteReadLimit();
			}

			Set<string> opts = Properties.asKeySet("org.bouncycastle.debug.est");
			if (opts.contains("input") || opts.contains("all"))
			{
				this.inputStream = new PrintingInputStream(this, source.getInputStream());
			}
			else
			{
				this.inputStream = source.getInputStream();
			}

			this.headers = new HttpUtil.Headers();
			this.lineBuffer = new byte[1024];

			process();
		}

		private void process()
		{
			//
			// Status line.
			//
			HttpVersion = readStringIncluding(' ');
			this.statusCode = int.Parse(readStringIncluding(' '));
			this.statusMessage = readStringIncluding('\n');


			//
			// Headers.
			//
			string line = readStringIncluding('\n');
			int i;
			while (line.Length > 0)
			{
				i = line.IndexOf(':');
				if (i > -1)
				{
					string k = Strings.toLowerCase(line.Substring(0, i).Trim()); // Header keys are case insensitive
					headers.add(k, line.Substring(i + 1).Trim());
				}
				line = readStringIncluding('\n');
			}


			contentLength = getContentLength();

			//
			// Concerned that different servers may or may not set a Content-length
			// for these success types. In this case we will arbitrarily set content length
			// to zero.
			//
			if (statusCode == 204 || statusCode == 202)
			{
				if (contentLength == null)
				{
					contentLength = 0L;
				}
				else
				{
					if (statusCode == 204 && contentLength > 0)
					{
						throw new IOException("Got HTTP status 204 but Content-length > 0.");
					}
				}
			}

			if (contentLength == null)
			{
				throw new IOException("No Content-length header.");
			}

			if (contentLength.Equals(ZERO))
			{

				//
				// The server is likely to hang up the socket and any attempt to read can
				// result in a broken pipe rather than an eof.
				// So we will return a dummy input stream that will return eof to anything that reads from it.
				//

				inputStream = new InputStreamAnonymousInnerClass(this);
			}

			if (contentLength != null)
			{
				if (contentLength < 0)
				{
					throw new IOException("Server returned negative content length: " + absoluteReadLimit);
				}

				if (absoluteReadLimit != null && contentLength >= absoluteReadLimit)
				{
					throw new IOException("Content length longer than absolute read limit: " + absoluteReadLimit + " Content-Length: " + contentLength);
				}
			}


			inputStream = wrapWithCounter(inputStream, absoluteReadLimit);
			//
			// Observed that some
			//
			if ("base64".Equals(getHeader("content-transfer-encoding"), StringComparison.OrdinalIgnoreCase))
			{
				inputStream = new CTEBase64InputStream(inputStream, getContentLength());
			}
		}

		public class InputStreamAnonymousInnerClass : InputStream
		{
			private readonly ESTResponse outerInstance;

			public InputStreamAnonymousInnerClass(ESTResponse outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public int read()
			{
				return -1;
			}
		}

		public virtual string getHeader(string key)
		{
			return headers.getFirstValue(key);
		}


//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: protected java.io.InputStream wrapWithCounter(final java.io.InputStream in, final System.Nullable<long> absoluteReadLimit)
		public virtual InputStream wrapWithCounter(InputStream @in, long? absoluteReadLimit)
		{
			return new InputStreamAnonymousInnerClass2(this, @in, absoluteReadLimit);
		}

		public class InputStreamAnonymousInnerClass2 : InputStream
		{
			private readonly ESTResponse outerInstance;

			private InputStream @in;
			private long? absoluteReadLimit;

			public InputStreamAnonymousInnerClass2(ESTResponse outerInstance, InputStream @in, long? absoluteReadLimit)
			{
				this.outerInstance = outerInstance;
				this.@in = @in;
				this.absoluteReadLimit = absoluteReadLimit;
			}

			public int read()
			{
				int i = @in.read();
				if (i > -1)
				{
					outerInstance.read++;
					if (absoluteReadLimit != null && outerInstance.read >= absoluteReadLimit.Value)
					{
						throw new IOException("Absolute Read Limit exceeded: " + absoluteReadLimit);
					}
				}
				return i;
			}

			public void close()
			{
				if (outerInstance.contentLength != null && outerInstance.contentLength - 1 > outerInstance.read)
				{
					throw new IOException("Stream closed before limit fully read, Read: " + outerInstance.read + " ContentLength: " + outerInstance.contentLength);
				}

				if (@in.available() > 0)
				{
					throw new IOException("Stream closed with extra content in pipe that exceeds content length.");
				}

				@in.close();
			}
		}


		public virtual string readStringIncluding(char until)
		{
			int c = 0;
			int j;
			do
			{
				j = inputStream.read();
				lineBuffer[c++] = (byte)j;
				if (c >= lineBuffer.Length)
				{
					throw new IOException("Server sent line > " + lineBuffer.Length);
				}
			} while ((char)j != until && j > -1);
			if (j == -1)
			{
				throw new EOFException();
			}

			return (StringHelper.NewString(lineBuffer, 0, c)).Trim();
		}

		public virtual ESTRequest getOriginalRequest()
		{
			return originalRequest;
		}

		public virtual HttpUtil.Headers getHeaders()
		{
			return headers;
		}

		public virtual string getHttpVersion()
		{
			return HttpVersion;
		}

		public virtual int getStatusCode()
		{
			return statusCode;
		}

		public virtual string getStatusMessage()
		{
			return statusMessage;
		}

		public virtual InputStream getInputStream()
		{
			return inputStream;
		}


		public virtual Source getSource()
		{
			return source;
		}

		public virtual long? getContentLength()
		{
			string v = headers.getFirstValue("Content-Length");
			if (string.ReferenceEquals(v, null))
			{
				return null;
			}
			try
			{
				return long.Parse(v);
			}
			catch (RuntimeException nfe)
			{
				throw new RuntimeException("Content Length: '" + v + "' invalid. " + nfe.getMessage());
			}
		}

		public virtual void close()
		{
			if (inputStream != null)
			{
				inputStream.close();
			}
			this.source.close();
		}


		public class PrintingInputStream : InputStream
		{
			private readonly ESTResponse outerInstance;

			internal readonly InputStream src;

			public PrintingInputStream(ESTResponse outerInstance, InputStream src)
			{
				this.outerInstance = outerInstance;
				this.src = src;
			}

			public virtual int read()
			{
				int i = src.read();
				JavaSystem.@out.print(((char)i).ToString());
				return i;
			}

			public virtual int available()
			{
				return src.available();
			}

			public virtual void close()
			{
				src.close();
			}
		}
	}

}