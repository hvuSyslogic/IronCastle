namespace org.bouncycastle.mail.smime
{


	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessable = org.bouncycastle.cms.CMSProcessable;
	using CRLFOutputStream = org.bouncycastle.mail.smime.util.CRLFOutputStream;

	/// <summary>
	/// a holding class for a BodyPart to be processed which does CRLF canocicalisation if 
	/// dealing with non-binary data.
	/// </summary>
	public class CMSProcessableBodyPartOutbound : CMSProcessable
	{
		private BodyPart bodyPart;
		private string defaultContentTransferEncoding;

		/// <summary>
		/// Create a processable with the default transfer encoding of 7bit 
		/// </summary>
		/// <param name="bodyPart"> body part to be processed </param>
		public CMSProcessableBodyPartOutbound(BodyPart bodyPart)
		{
			this.bodyPart = bodyPart;
		}

		/// <summary>
		/// Create a processable with the a default transfer encoding of
		/// the passed in value. 
		/// </summary>
		/// <param name="bodyPart"> body part to be processed </param>
		/// <param name="defaultContentTransferEncoding"> the new default to use. </param>
		public CMSProcessableBodyPartOutbound(BodyPart bodyPart, string defaultContentTransferEncoding)
		{
			this.bodyPart = bodyPart;
			this.defaultContentTransferEncoding = defaultContentTransferEncoding;
		}

		public virtual void write(OutputStream @out)
		{
			try
			{
				if (SMIMEUtil.isCanonicalisationRequired((MimeBodyPart)bodyPart, defaultContentTransferEncoding))
				{
					@out = new CRLFOutputStream(@out);
				}

				bodyPart.writeTo(@out);
			}
			catch (MessagingException e)
			{
				throw new CMSException("can't write BodyPart to stream.", e);
			}
		}

		public virtual object getContent()
		{
			return bodyPart;
		}
	}

}