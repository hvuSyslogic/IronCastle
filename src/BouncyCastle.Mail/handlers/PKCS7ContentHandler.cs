namespace org.bouncycastle.mail.smime.handlers
{


	public class PKCS7ContentHandler : DataContentHandler
	{
		private readonly ActivationDataFlavor _adf;
		private readonly DataFlavor[] _dfs;

		public PKCS7ContentHandler(ActivationDataFlavor adf, DataFlavor[] dfs)
		{
			_adf = adf;
			_dfs = dfs;
		}

		public virtual object getContent(DataSource ds)
		{
			return ds.getInputStream();
		}

		public virtual object getTransferData(DataFlavor df, DataSource ds)
		{
			if (_adf.Equals(df))
			{
				return getContent(ds);
			}
			else
			{
				return null;
			}
		}

		public virtual DataFlavor[] getTransferDataFlavors()
		{
			return _dfs;
		}

		public virtual void writeTo(object obj, string mimeType, OutputStream os)
		{
			if (obj is MimeBodyPart)
			{
				try
				{
					((MimeBodyPart)obj).writeTo(os);
				}
				catch (MessagingException ex)
				{
					throw new IOException(ex.Message);
				}
			}
			else if (obj is byte[])
			{
				os.write((byte[])obj);
			}
			else if (obj is InputStream)
			{
				int b;
				InputStream @in = (InputStream)obj;

				if (!(@in is BufferedInputStream))
				{
					@in = new BufferedInputStream(@in);
				}

				while ((b = @in.read()) >= 0)
				{
					os.write(b);
				}

				@in.close();
			}
			else if (obj is SMIMEStreamingProcessor)
			{
				SMIMEStreamingProcessor processor = (SMIMEStreamingProcessor)obj;

				processor.write(os);
			}
			else
			{
				// TODO it would be even nicer if we could attach the object to the exception
				//     as well since in deeply nested messages, it is not always clear which
				//     part caused the problem. Thus I guess we would have to subclass the
				//     IOException

				throw new IOException("unknown object in writeTo " + obj);
			}
		}
	}

}