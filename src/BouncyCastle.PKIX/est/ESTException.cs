using System;

namespace org.bouncycastle.est
{

	/// <summary>
	/// Exception emitted by EST classes.
	/// </summary>
	public class ESTException : IOException
	{
		private Exception cause;

		private InputStream body;
		private int statusCode;

		private const long MAX_ERROR_BODY = 8192;

		public ESTException(string msg) : this(msg, null)
		{
		}

		public ESTException(string msg, Exception cause) : base(msg)
		{
			this.cause = cause;
			body = null;
			statusCode = 0;
		}

		public ESTException(string message, Exception cause, int statusCode, InputStream body) : base(message)
		{
			this.cause = cause;
			this.statusCode = statusCode;
			if (body != null)
			{
				byte[] b = new byte[8192];
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				try
				{
					int i = body.read(b);
					while (i >= 0)
					{
						if (bos.size() + i > MAX_ERROR_BODY)
						{
							i = (int)MAX_ERROR_BODY - bos.size();
							bos.write(b, 0, i);
							break;
						}
						bos.write(b, 0, i);
						i = body.read(b);
					}
					bos.flush();
					bos.close();
					this.body = new ByteArrayInputStream(bos.toByteArray());
					body.close();
				}
				catch (Exception)
				{
					// This is a best effort read, input stream could be dead by this point.
				}
			}
			else
			{
				this.body = null;
			}
		}

		public virtual Exception getCause()
		{
			return cause;
		}

		public virtual string getMessage()
		{
			return base.Message + " HTTP Status Code: " + statusCode;
		}

		public virtual InputStream getBody()
		{
			return body;
		}

		public virtual int getStatusCode()
		{
			return statusCode;
		}

	}

}