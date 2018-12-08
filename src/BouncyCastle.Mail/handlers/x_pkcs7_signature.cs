namespace org.bouncycastle.mail.smime.handlers
{


	public class x_pkcs7_signature : DataContentHandler
	{

		/*  
		 *  
		 *  VARIABLES
		 *  
		 */ 

		private static readonly ActivationDataFlavor ADF;
		private static readonly DataFlavor[] ADFs;

		static x_pkcs7_signature()
		{
			ADF = new ActivationDataFlavor(typeof(MimeBodyPart), "application/x-pkcs7-signature", "Signature");
			ADFs = new DataFlavor[] {ADF};
		}

		public virtual object getContent(DataSource _ds)
		{
			return _ds.getInputStream();
		}

		public virtual object getTransferData(DataFlavor _df, DataSource _ds)
		{
			if (ADF.Equals(_df))
			{
				return getContent(_ds);
			}
			else
			{
				return null;
			}
		}

		public virtual DataFlavor[] getTransferDataFlavors()
		{
			return ADFs;
		}

		public virtual void writeTo(object _obj, string _mimeType, OutputStream _os)
		{
			if (_obj is MimeBodyPart)
			{
				try
				{
					((MimeBodyPart)_obj).writeTo(_os);
				}
				catch (MessagingException ex)
				{
					throw new IOException(ex.Message);
				}
			}
			else if (_obj is byte[])
			{
				_os.write((byte[])_obj);
			}
			else if (_obj is InputStream)
			{
				int b;
				InputStream @in = (InputStream)_obj;

				while ((b = @in.read()) >= 0)
				{
					_os.write(b);
				}
			}
			else
			{
				throw new IOException("unknown object in writeTo " + _obj);
			}
		}
	}

}