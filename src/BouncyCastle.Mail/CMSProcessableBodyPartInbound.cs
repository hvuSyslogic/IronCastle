namespace org.bouncycastle.mail.smime
{


	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessable = org.bouncycastle.cms.CMSProcessable;

	/// <summary>
	/// a holding class for a BodyPart to be processed which does CRLF canonicalisation if
	/// dealing with non-binary data.
	/// </summary>
	public class CMSProcessableBodyPartInbound : CMSProcessable
	{
		private readonly BodyPart bodyPart;
		private readonly string defaultContentTransferEncoding;

		/// <summary>
		/// Create a processable with the default transfer encoding of 7bit 
		/// </summary>
		/// <param name="bodyPart"> body part to be processed </param>
		public CMSProcessableBodyPartInbound(BodyPart bodyPart) : this(bodyPart, "7bit")
		{
		}

		/// <summary>
		/// Create a processable with the a default transfer encoding of
		/// the passed in value. 
		/// </summary>
		/// <param name="bodyPart"> body part to be processed </param>
		/// <param name="defaultContentTransferEncoding"> the new default to use. </param>
		public CMSProcessableBodyPartInbound(BodyPart bodyPart, string defaultContentTransferEncoding)
		{
			this.bodyPart = bodyPart;
			this.defaultContentTransferEncoding = defaultContentTransferEncoding;
		}

		public virtual void write(OutputStream @out)
		{
			try
			{
				SMIMEUtil.outputBodyPart(@out, true, bodyPart, defaultContentTransferEncoding);
			}
			catch (MessagingException e)
			{
				throw new CMSException("can't write BodyPart to stream: " + e, e);
			}
		}

		public virtual object getContent()
		{
			return bodyPart;
		}
	}

}